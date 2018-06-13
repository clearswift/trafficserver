/** @file

 A brief file description

 @section license License

 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include "UpstreamConnectHandler.h"

#include "P_Net.h"

namespace
{
constexpr int64_t CONNECT_LENGTH_LENGTH { 14 };
}

UpstreamConnectHander::UpstreamConnectHander(SSLNetVConnection *inSslNetVConn) :
    ConnectHandler(inSslNetVConn)
{
  connectBuffer = new_MIOBuffer();
  connectReader = connectBuffer->alloc_reader();
}

/**
 * If an upstream CONNECT has been set then send this to the upstream proxy and
 * read the response which could include a body
 *
 * Returns:
 * EVENT_NONE - Operation is complete
 * Any other return will be used by the SSLNetVConnection
 */
int UpstreamConnectHander::doWork()
{

  // if have not checked if the CONNECT request has been set
  if (!checkedForValidConnect) {
    int hostLength = 0;
    this->connectRequest.host_get(&hostLength);

    checkedForValidConnect = true;

    // if the host is not set - assume the CONNECT has not been set up (direct connection to server)
    // note - do not use valid() on the connectRequest as this will always return true
    if (hostLength == 0) {
      Debug("upstream_connect_handler", "%p Upstream proxy not set", sslNetVConn);
      workComplete = true;
      return EVENT_NONE;
    } else {
      Debug("upstream_connect_handler", "%p Upstream proxy set", sslNetVConn);
    }
  }

  int ret = EVENT_NONE;

  if (!sentUpstreamConnect) {
    ret = sendUpstreamConnect();
  }

  if (ret == EVENT_NONE && !upstreamConnectResponseRead) {
    ret = readUpstreamConnectResponse();
  }

  if (ret == EVENT_NONE && !upstreamBodyRead && connectResponseBodyLength > 0) {
    ret = readUpstreamConnectResponseBody();
  }

  if (ret == EVENT_NONE) {

    // if the CONNECT response was not OK
    if (responseStatus != HTTP_STATUS_OK) {
      Debug("upstream_connect_handler", "Upstream proxy returned error %d", responseStatus);
      ret = EVENT_ERROR;
    }

    Debug("upstream_connect_handler", "Upstream proxy processed");
    workComplete = true;
  }

  return ret;
}

/**
 * Send the CONNECT to the upstream proxy
 *
 * Returns:
 * EVENT_NONE - The CONNECT request has been sent
 * VC_EVENT_WRITE_READY - The CONNECT request has not been fully sent
 * EVENT_ERROR - Write error occurred
 */
int UpstreamConnectHander::sendUpstreamConnect()
{
  if (connectSize == 0) {
    connectSize = writeHeaderIntoBuffer(&this->connectRequest, connectBuffer);
  }

  int ret = writeBufferToNetwork(connectReader, connectSize, connectWritten);

  if (ret == EVENT_NONE) {
    freeGeneral();

    sentUpstreamConnect = true;
  }

  return ret;
}

/**
 * Read the upstream CONNECT response
 *
 * Returns:
 * EVENT_NONE - The CONNECT response has been read
 * SSL_HANDSHAKE_WANT_READ - The CONNECT response has not been fully read
 * EVENT_ERROR - Read error occurred
 */
int UpstreamConnectHander::readUpstreamConnectResponse()
{
  int ret = EVENT_NONE;

  if (connectBuffer == nullptr) {
    connectBuffer = new_MIOBuffer();
    connectReader = connectBuffer->alloc_reader();

    connectParser = reinterpret_cast<HTTPParser *>(ats_malloc(sizeof(HTTPParser)));
    http_parser_init(connectParser);
  }

  ret = readHeadersFromNetwork(false, connectResponse, connectBuffer, connectReader, connectParser);

  if (ret == EVENT_NONE) {
    this->connectResponseParseComplete = true;

    responseStatus = this->connectResponse->status_get();
    upstreamConnectResponseRead = true;
  }

  if (ret == EVENT_NONE) {
    const MIMEField *field = connectResponse->field_find("content-length", CONNECT_LENGTH_LENGTH);

    // if a content-length header is found
    if (field) {
      connectResponseBodyLength = field->value_get_int64();
    }

    if (connectResponseBodyLength > 0) {
      Debug("upstream_connect_handler", "CONNECT response body detected of length %" PRId64, connectResponseBodyLength);

      connectResponseBody = new char[connectResponseBodyLength];

      drainConnectReaderIntoBody();
    }
  }

  return ret;
}

/**
 * Read any remaining data from the reader and copy into the body buffer
 */
void UpstreamConnectHander::drainConnectReaderIntoBody()
{
  int64_t availToRead = connectReader->block_read_avail();
  while (availToRead > 0) {
    char *start = connectReader->start();
    memcpy(connectResponseBody + connectBodyRead, start, availToRead);
    connectReader->consume(availToRead);

    connectBodyRead += availToRead;

    availToRead = connectReader->block_read_avail();
  }

  Debug("detail_upstream_connect_handler", "Drained %" PRId64 " bytes from the reader", connectBodyRead);
}

/**
 * Read the upstream CONNECT body
 * Note that chunked encoded bodies are not supported
 *
 * Returns:
 * EVENT_NONE - The body has been read
 * SSL_HANDSHAKE_WANT_READ - The body has not been fully read
 * EVENT_ERROR - Read error occurred
 */
int UpstreamConnectHander::readUpstreamConnectResponseBody()
{

  int ret = readStringFromNetwork(connectResponseBody, connectResponseBodyLength, connectBodyRead);

  if (ret == EVENT_NONE) {
    upstreamBodyRead = true;
  }

  return ret;
}
