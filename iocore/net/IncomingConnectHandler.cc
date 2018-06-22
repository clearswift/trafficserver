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

#include "IncomingConnectHandler.h"

#include "I_EventSystem.h"
#include "P_Net.h"
#include "InkAPIInternal.h"

IncomingConnectHandler::IncomingConnectHandler(SSLNetVConnection *inSslNetVConn) :
    ConnectHandler(inSslNetVConn)
{
  connectBuffer = new_MIOBuffer();
  connectReader = connectBuffer->alloc_reader();

  connectParser = reinterpret_cast<HTTPParser *>(ats_malloc(sizeof(HTTPParser)));
  http_parser_init(connectParser);
}

/**
 * Detects whether connection is raw SSL or a CONNECT
 * Reads the CONNECT and sends back the response
 *
 * Returns:
 * EVENT_NONE - Operation is complete
 * Any other return will be used by the SSLNetVConnection
 */
int IncomingConnectHandler::doWork()
{
  int ret = EVENT_NONE;

  // if not checked for a CONNECT request
  if (!this->checkedForConnect) {
    ret = detectConnect();

    if (ret != EVENT_NONE) {
      return ret;
    }
    // if the CONNECT detection is complete and it is not a CONNECT
    else if (this->checkedForConnect && !this->connectReceived) {
      return EVENT_NONE;
    }
  }

  if (!this->connectRequestParseComplete) {
    ret = parseIncomingConnect();
  }

  if (ret == EVENT_NONE && this->connectRequestParseComplete) {
    ret = sendConnectResponse();
  }

  return ret;
}

/**
 * Detects whether the incoming connections is raw SSL or a CONNECT
 *
 * Returns:
 * EVENT_NONE - Detection complete
 * SSL_HANDSHAKE_WANT_READ - More data required for detection
 * EVENT_ERROR - Error occurred
 */
int IncomingConnectHandler::detectConnect()
{
  int ret = EVENT_NONE;

  char rawBuffer[1];

  int r = recv(sslNetVConn->con.fd, rawBuffer, 1, MSG_PEEK);

  if (r <= 0) {
    if (r == 0 || r == -EAGAIN || r == -ENOTCONN) {
      ret = SSL_HANDSHAKE_WANT_READ;
    } else {
      ret = EVENT_ERROR;
    }
  } else {
    this->checkedForConnect = true;

    // if raw SSL has been detected
    if (rawBuffer[0] == SSL_OP_HANDSHAKE) {
      Debug("incoming_connect_handler", "Raw SSL detected");
      this->workComplete = true;
    } else {
      Debug("incoming_connect_handler", "CONNECT detected");
      this->connectReceived = true;
    }
  }

  return ret;
}

/**
 * Reads and parses the incoming CONNECT request
 * Also invokes the TS_EVENT_CONNECT_RECEIVED event
 *
 * Returns:
 * EVENT_NONE - Parsing is complete
 * SSL_HANDSHAKE_WANT_READ - More data required
 * EVENT_ERROR - Error occurred
 */
int IncomingConnectHandler::parseIncomingConnect()
{
  int ret = EVENT_NONE;

  if (!this->connectRequestParseComplete) {
    ret = readHeadersFromNetwork(true, &connectRequest, connectBuffer, connectReader, connectParser);

    if (ret == EVENT_NONE) {
      this->connectRequestParseComplete = true;

      freeGeneral();

      APIHook *hook = ssl_hooks->get(TS_CONNECT_RECEIVED_INTERNAL_HOOK);

      if (hook != nullptr) {
        hook->invoke(TS_EVENT_CONNECT_RECEIVED, sslNetVConn);
      }
    }
  }

  return ret;
}

/**
 * Sends the CONNECT response
 *
 * Returns:
 * EVENT_NONE - Response has been sent
 * VC_EVENT_WRITE_READY - The response has not been fully sent
 * EVENT_ERROR - Error occurred
 */
int IncomingConnectHandler::sendConnectResponse()
{
  if (connectBuffer == nullptr) {
    connectBuffer = new_MIOBuffer();
    connectReader = connectBuffer->alloc_reader();

    int reasonLength;
    this->connectResponse->reason_get(&reasonLength);
    if (reasonLength == 0) {
      // No reason set, default to reason for status
      const char* reason = http_hdr_reason_lookup(this->connectResponse->status_get());
      this->connectResponse->reason_set(reason, static_cast<int>(strlen(reason)));
    }

    if (this->connectResponseBodyLength > 0) {
      this->connectResponse->set_content_length(this->connectResponseBodyLength);
    }

    connectSize = writeHeaderIntoBuffer(connectResponse, connectBuffer);
  }

  int ret = EVENT_NONE;

  // if the whole CONNECT response has not been written
  if (connectWritten != connectSize) {
    ret = writeBufferToNetwork(connectReader, connectSize, connectWritten);
  }

  if (ret == EVENT_NONE) {
    // if there is a CONNECT response body and it has not been fully written
    if (this->connectResponseBodyLength > 0 && connectResponseBodyLength != connectBodyWritten) {
      ret = writeStringToNetwork(this->connectResponseBody, this->connectResponseBodyLength, this->connectBodyWritten);
    }

    if (ret == EVENT_NONE) {
      this->workComplete = true;
      Debug("incoming_connect_handler", "CONNECT processed");
    }
  }

  return ret;
}
