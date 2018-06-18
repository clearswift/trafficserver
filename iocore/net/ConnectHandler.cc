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

#include "ConnectHandler.h"

#include "I_Event.h"
#include "I_VConnection.h"
#include "P_Net.h"

namespace
{
constexpr int64_t BUFFER_SIZE { 4096 };
}

ConnectHandler::ConnectHandler(SSLNetVConnection *inSslNetVConn) :
    sslNetVConn(inSslNetVConn)
{
  this->connectRequestHdrHeap = new HTTPHdr;
  this->connectRequestHdrHeap->m_heap = new_HdrHeap();
  this->connectRequest.m_heap = this->connectRequestHdrHeap->m_heap;
  this->connectRequest.create(HTTP_TYPE_REQUEST);

  this->connectResponseHdrHeap = new HTTPHdr;
  this->connectResponseHdrHeap->m_heap = new_HdrHeap();

  this->connectResponse = new HTTPHdr;
  this->connectResponse->m_heap = this->connectResponseHdrHeap->m_heap;
  this->connectResponse->create(HTTP_TYPE_RESPONSE);
  this->connectResponse->status_set(HTTP_STATUS_OK);

  this->connectResponseBodyArray = new std::vector<char>;
}

ConnectHandler::~ConnectHandler()
{
  freeMemory();
}

/**
 * Writes the passed header object into the passed buffer
 *
 * Returns the total length of the buffer
 */
int ConnectHandler::writeHeaderIntoBuffer(HTTPHdr *h, MIOBuffer *b)
{
  int bufindex;
  int dumpoffset;
  int done, tmp;
  IOBufferBlock *block;

  dumpoffset = 0;
  do {
    bufindex = 0;
    tmp = dumpoffset;
    block = b->get_current_block();
    ink_assert(block->write_avail() > 0);
    done = h->print(block->start(), block->write_avail(), &bufindex, &tmp);
    dumpoffset += bufindex;
    ink_assert(bufindex > 0);
    b->fill(bufindex);
    if (!done) {
      b->add_block();
    }
  } while (!done);

  return dumpoffset;
}

/**
 * Reads from the buffer reader and writes the data to the network
 *
 * Returns:
 * EVENT_NONE - All the data has been read and written
 * VC_EVENT_WRITE_READY - Not all the data has been written yet
 * EVENT_ERROR - A write error occurred
 */
int ConnectHandler::writeBufferToNetwork(IOBufferReader *bufferReader, int64_t totalBufferSize, int64_t &totalWritten)
{

  int ret = EVENT_NONE;

  int64_t toWrite = BUFFER_SIZE;
  int64_t availToRead = bufferReader->read_avail();

  if (toWrite > availToRead) {
    toWrite = availToRead;
  }

  int64_t written = socketManager.write(sslNetVConn->con.fd, (void*) (bufferReader->start()), toWrite);

  if (written < 0) {
    ret = EVENT_ERROR;
  } else {
    Debug("detail_connect_handler", "written %" PRId64, written);

    totalWritten += written;
    bufferReader->consume(written);

    if (totalWritten != totalBufferSize) {
      // cannot use SSL_HANDSHAKE_WANT_WRITE as this vconn would be removed from the write checks
      ret = VC_EVENT_WRITE_READY;
    }
  }

  return ret;
}

/**
 * Writes the passed string to the network
 *
 * Returns:
 * EVENT_NONE - The entire string has been read and written
 * VC_EVENT_WRITE_READY - Not all the string has been written yet
 * EVENT_ERROR - A write error occurred
 */
int ConnectHandler::writeStringToNetwork(const char *stringBuffer, int64_t stringLength, int64_t &totalWritten)
{

  int64_t toWrite = BUFFER_SIZE;
  if (stringLength - totalWritten < BUFFER_SIZE) {
    toWrite = stringLength - totalWritten;
  }

  int64_t written = socketManager.write(sslNetVConn->con.fd, (void*) (stringBuffer + totalWritten), toWrite);

  int ret = EVENT_NONE;

  if (written < 0) {
    ret = EVENT_ERROR;
  } else {
    Debug("detail_connect_handler", "written %" PRId64, written);

    totalWritten += written;

    if (totalWritten != stringLength) {
      // cannot use SSL_HANDSHAKE_WANT_WRITE as this vconn would be removed from the write checks
      ret = VC_EVENT_WRITE_READY;
    }
  }

  return ret;
}

/**
 * Read the CONNECT request or response headers from the network
 * The headers are then parsed to determine whether they are complete
 *
 * Returns:
 * EVENT_NONE - The CONNECT request or response headers have been fully read
 * SSL_HANDSHAKE_WANT_READ - The entire request or response has not been read
 * EVENT_ERROR - A read or parse error occurred
 */
int ConnectHandler::readHeadersFromNetwork(bool isRequest, HTTPHdr *headers, MIOBuffer *hdrIoBuffer,
    IOBufferReader *headerIoBufferReader, HTTPParser *httpParser)
{
  int ret = EVENT_NONE;

  int totalRead = readIntoBuffer(hdrIoBuffer);

  if (totalRead < 0) {
    ret = EVENT_ERROR;
  }
  // this happens once each time SSL_HANDSHAKE_WANT_READ is returned in the parsing code below
  else if (totalRead == 0) {
    ret = SSL_HANDSHAKE_WANT_READ;
  } else {
    int bytesUsed = 0;
    ParseResult result = PARSE_RESULT_ERROR;

    if (isRequest) {
      result = headers->parse_req(httpParser, headerIoBufferReader, &bytesUsed, false);
    } else {
      result = headers->parse_resp(httpParser, headerIoBufferReader, &bytesUsed, false);
    }

    if (result == PARSE_RESULT_CONT) {
      // for some reason returning this causes a single read event to be scheduled immediately
      ret = SSL_HANDSHAKE_WANT_READ;
    } else if (result == PARSE_RESULT_ERROR) {
      ret = EVENT_ERROR;
    }
  }

  return ret;
}

/**
 * Reads from the network into the passed buffer
 *
 * Returns:
 * The amount of data read
 * -1 if an error occurs
 */
int64_t ConnectHandler::readIntoBuffer(MIOBuffer *ioBuffer)
{
  int64_t totalRead = 0;
  int64_t read = 0;
  int64_t bufLength = 0;

  // read until there is no more data available
  // note that have to loop here because if just read once there
  // is a chance that would not receive another event indicating more data
  do {
    IOBufferBlock *b = ioBuffer->get_current_block();
    bufLength = b->write_avail();
    char *buffer = b->_end;

    read = socketManager.read(sslNetVConn->con.fd, buffer, bufLength);

    if (read > 0) {
      Debug("detail_connect_handler", "read %" PRId64, read);

      totalRead += read;

      ioBuffer->fill(read);
      ioBuffer->add_block();
    }
  } while (read > 0);

  if (read < 0) {
    if (read != -EAGAIN && read != -ENOTCONN) {
      totalRead = -1;
    }
  }

  return totalRead;
}

/**
 * Read from the network into the passed string
 *
 * Returns:
 * EVENT_NONE - The entire string has been read
 * SSL_HANDSHAKE_WANT_READ - The entire string has not been read
 * EVENT_ERROR - A read occurred
 */
int ConnectHandler::readFromNetworkIntoArray(std::vector<char> *dataArray, int64_t stringLength, int64_t &totalRead)
{

  int ret = EVENT_NONE;
  int64_t read = 0;

  do {
    int64_t toRead = BUFFER_SIZE;
    if (stringLength - totalRead < BUFFER_SIZE) {
      toRead = stringLength - totalRead;
    }

    read = socketManager.read(sslNetVConn->con.fd, &((*dataArray)[totalRead]), toRead);

    Debug("detail_connect_handler", "read %" PRId64, read);

    if (read > 0) {
      totalRead += read;
    }
  } while (read > 0 && totalRead < stringLength);

  if (read < 0) {
    if (read != -EAGAIN && read != -ENOTCONN) {
      ret = EVENT_ERROR;
    }
  }

  if (ret == EVENT_NONE && totalRead < stringLength) {
    ret = SSL_HANDSHAKE_WANT_READ;
  }

  return ret;
}

/**
 * Frees the general purpose members
 */
void ConnectHandler::freeGeneral()
{
  if (connectParser != nullptr) {
    http_parser_clear(connectParser);
    ats_free(connectParser);
    connectParser = nullptr;
  }

  if (connectReader) {
    connectBuffer->dealloc_reader(connectReader);
  }
  connectReader = nullptr;

  if (connectBuffer) {
    free_MIOBuffer(connectBuffer);
  }
  connectBuffer = nullptr;

  connectSize = 0;
  connectWritten = 0;
}

/**
 * Free all the memory
 */
void ConnectHandler::freeMemory()
{
  if (connectRequestHdrHeap != nullptr) {
    connectRequestHdrHeap->m_heap->destroy();
    delete connectRequestHdrHeap;
    connectRequestHdrHeap = nullptr;
  }
  if (connectRequest.valid()) {
    connectRequest.reset();
  }

  // only free the response if this object owns it
  if (ownConnectResponse) {
    if (connectResponseHdrHeap != nullptr) {
      connectResponseHdrHeap->m_heap->destroy();
      delete connectResponseHdrHeap;
      connectResponseHdrHeap = nullptr;
    }

    delete connectResponse;
    connectResponse = nullptr;
  }

  if (ownConnectResponseBodyArray) {
    delete connectResponseBodyArray;
    connectResponseBodyArray = nullptr;
  }

  freeGeneral();
}
