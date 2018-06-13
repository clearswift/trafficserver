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

UpstreamConnectHander::UpstreamConnectHander(SSLNetVConnection *inSslNetVConn) :
		ConnectHandler(inSslNetVConn) {
	connectBuffer = new_MIOBuffer();
	connectReader = connectBuffer->alloc_reader();
}

/**
 * If an upstream CONNECT has been set then send this to the upstream proxy and
 read the response
 */
int UpstreamConnectHander::doWork() {
	if (!checkedForValidConnect) {
		int hostLength = 0;
		this->connectRequest.host_get(&hostLength);

		checkedForValidConnect = true;

		// if the host is not set - assume the CONNECT has not been set up (direct connection to server)
		// note - do not use valid() on the connectRequest as this will always return true
		if (hostLength == 0) {
			Debug("upstream_connect_handler", "%p Upstream proxy not set",
					sslNetVConn);
			workComplete = true;
			return EVENT_NONE;
		}
		else {
			Debug("upstream_connect_handler", "%p Upstream proxy set",
					sslNetVConn);
		}
	}

	Debug("upstream_connect_handler", "%p DOWORK", sslNetVConn);

	int ret = EVENT_NONE;

	if (!sentUpstreamConnect) {
		ret = sendUpstreamConnect();
	}

	if (ret == EVENT_NONE && !upstreamConnectResponseRead) {
		ret = readUpstreamConnectResponse();
	}

	if (ret == EVENT_NONE && !upstreamBodyRead
			&& connectResponseBodyLength > 0) {
		ret = readUpstreamConnectResponseBody();
	}

	if (ret == EVENT_NONE) {
		if (responseStatus != HTTP_STATUS_OK) {
			Debug("upstream_connect_handler",
					"Upstream proxy returned error %d", responseStatus);
			ret = EVENT_ERROR;
		}

		Debug("upstream_connect_handler", "Upstream proxy processed");
		workComplete = true;
	}

	return ret;
}

/**
 * Send the CONNECT to the upstream proxy

 Returns:
 EVENT_ERROR for errors (upstream proxy write error)
 SSL_HANDSHAKE_WANT_READ if completed the send and now requires the response
 */
int UpstreamConnectHander::sendUpstreamConnect() {
	if (connectSize == 0) {
		connectSize = write_header_into_buffer(&this->connectRequest,
				connectBuffer);
	}

	int ret = writeBufferToNetwork(connectReader, connectSize, connectWritten);

	if (ret == EVENT_NONE) {
		freeConnect();

		sentUpstreamConnect = true;
		ret = SSL_HANDSHAKE_WANT_READ;
	}

	return ret;
}

/**
 * Read the upstream connect response
 Returns:
 EVENT_ERROR for errors (upstream proxy read error or returned status code is bad)
 SSL_HANDSHAKE_WANT_READ if more data is required
 */
int UpstreamConnectHander::readUpstreamConnectResponse() {
	int ret = EVENT_NONE;

	if (connectBuffer == nullptr) {
		connectBuffer = new_MIOBuffer();
		connectReader = connectBuffer->alloc_reader();

		connectParser = reinterpret_cast<HTTPParser *>(ats_malloc(
				sizeof(HTTPParser)));
		http_parser_init (connectParser);
	}

	ret = readHeadersFromNetwork(false, connectResponse, connectBuffer,
			connectReader, connectParser);

	if (ret == EVENT_NONE) {
		this->connectResponseParseComplete = true;

		responseStatus = this->connectResponse->status_get();
		upstreamConnectResponseRead = true;
	}

	if (ret == EVENT_NONE) {
		const MIMEField *field = connectResponse->field_find("content-length",
				14);
		if (field) {
			connectResponseBodyLength = field->value_get_int64();
		}

		if (connectResponseBodyLength > 0) {
			Debug("upstream_connect_handler",
					"CONNECT response body detected of length %" PRId64,
					connectResponseBodyLength);
			
			connectResponseBody = new char[connectResponseBodyLength];
		}
	}

	return ret;
}

int UpstreamConnectHander::readUpstreamConnectResponseBody() {

	int ret = readStringFromNetwork(connectResponseBody,
			connectResponseBodyLength, connectBodyRead);

	if (ret == EVENT_NONE) {
		upstreamBodyRead = true;
	}

	return ret;
}
