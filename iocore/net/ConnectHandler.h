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

/****************************************************************************

 ConnectHandler.h

 Base class for handling CONNECT requests and responses

 ****************************************************************************/

#if !defined(_ConnectHandler_h_)
#define _ConnectHandler_h_

#include <vector>

#include "HTTP.h"
#include "I_IOBuffer.h"
#include "I_SocketManager.h"

class SSLNetVConnection;

class ConnectHandler
{
public:
  ConnectHandler(SSLNetVConnection *inSslNetVConn);

  virtual ~ConnectHandler();

  HTTPHdr *getConnectRequest()
  {
    return &connectRequest;
  }

  HTTPHdr *getConnectResponse()
  {
    return connectResponse;
  }

  void setConnectResponseBody(char *body, int64_t length)
  {
    connectResponseBodyLength = length;
    connectResponseBody = body;
  }

  const char *getConnectResponseBody(int64_t *length)
  {
    *length = connectResponseBodyLength;
    return connectResponseBody;
  }

  bool getConnectRequestParseComplete()
  {
    return connectRequestParseComplete;
  }

  bool getConnectResponseParseComplete()
  {
    return connectResponseParseComplete;
  }

  bool getWorkComplete()
  {
    return workComplete;
  }

  /**
   * Override the CONNECT response buffers
   * The CONNECT response buffers are initially maintained internally
   * This method allows external buffers to be used instead
   */
  void setConnectResponse(HdrHeapSDKHandle *buffer, HTTPHdr *headers)
  {
    if (ownConnectResponse) {
      connectResponseHdrHeap->m_heap->destroy();
      delete connectResponseHdrHeap;
      delete connectResponse;
    }

    connectResponseHdrHeap = buffer;
    connectResponse = headers;

    ownConnectResponse = false;
  }

  /**
   * Override the CONNECT response body string
   * The CONNECT response body is initially maintained internally
   * This method allows an external string to be used instead
   */
  void setConnectResponseBodyArray(std::vector<char> *bodyArray)
  {
    if (ownConnectResponseBodyArray) {
      delete connectResponseBodyArray;
    }

    connectResponseBodyArray = bodyArray;

    ownConnectResponseBodyArray = false;
  }

  // Overridden by derived classes
  virtual int doWork() = 0;

protected:
  int writeHeaderIntoBuffer(HTTPHdr *h, MIOBuffer *b);

  int writeBufferToNetwork(IOBufferReader *bufferReader, int64_t totalBufferSize, int64_t &totalWritten);

  int writeStringToNetwork(const char *stringBuffer, int64_t stringLength, int64_t &totalWritten);

  int readHeadersFromNetwork(bool isRequest, HTTPHdr *headers, MIOBuffer *hdrIoBuffer,
      IOBufferReader *headerIoBufferReader, HTTPParser *httpParser);

  int64_t readIntoBuffer(MIOBuffer *ioBuffer);

  int readFromNetworkIntoArray(std::vector<char> *dataArray, int64_t stringLength, int64_t &totalRead);

  void freeGeneral();

  void freeMemory();

  // pointer to the SSL NetV Connection
  SSLNetVConnection *sslNetVConn = nullptr;

  // request CONNECT buffers
  HdrHeapSDKHandle *connectRequestHdrHeap = nullptr;
  HTTPHdr connectRequest;

  // response CONNECT buffers
  HdrHeapSDKHandle *connectResponseHdrHeap = nullptr;
  HTTPHdr *connectResponse = nullptr;

  // whether this class owns the response buffers
  bool ownConnectResponse = true;

  // body buffer and related variables
  char *connectResponseBody = nullptr;
  int64_t connectResponseBodyLength = 0;
  int64_t connectBodyWritten = 0;
  int64_t connectBodyRead = 0;

  // general use buffer, reader and parser
  MIOBuffer *connectBuffer = nullptr;
  IOBufferReader *connectReader = nullptr;
  HTTPParser *connectParser = nullptr;
  int64_t connectSize = 0;
  int64_t connectWritten = 0;

  // holds the body that is read from the network
  std::vector<char> *connectResponseBodyArray = nullptr;

  // whether this class owns the body array
  bool ownConnectResponseBodyArray = true;

  // whether parsing is complete
  bool connectRequestParseComplete = false;
  bool connectResponseParseComplete = false;

  // whether the CONNECT handling is complete
  bool workComplete = false;
};

#endif /* _ConnectHandler_h_ */
