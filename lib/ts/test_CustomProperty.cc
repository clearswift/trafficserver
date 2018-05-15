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

#include "ts/CustomProperty.h"

void intDelete(void*f)
{
  delete (int*)f;
}

class MyValue
{
public:
  MyValue(char c = '\0') : m_c(c) {}
  ~MyValue() {}
  bool operator==(const MyValue& other) { return this->m_c == other.m_c; }
  bool operator!=(const MyValue& other) { return !( *this == other);     }
  static int constructed;
  static int destroyed;
private:
  char m_c;
  MyValue(const MyValue&);
  MyValue& operator=(const MyValue&);
};


int destroyedByMap = 0;


void resetCounts() { 
  destroyedByMap = 0;
}

void destroyMyValue(void* mv) { 
  if (mv != nullptr) {
    delete static_cast<MyValue*>(mv); 
    destroyedByMap++;
  }
}

void verify(bool condition, const char* errorMsg = "") { 
  if (!condition) { 
    printf("test_CustomProperty FAILED: %s\n", errorMsg); 
    exit(1); 
  }   
}

int
main() 
{
  // Test expectations for addition and retrieval
  {
    CustomProperties cp;
    cp.add("a", new MyValue('a'), destroyMyValue);
    cp.add("b", new MyValue('b'), destroyMyValue);
    cp.add("a", new MyValue('x'), destroyMyValue);
    verify( cp.get("a") != nullptr );
    verify( cp.get("b") != nullptr );
    verify( cp.get("c") == nullptr );
    verify( (*static_cast<MyValue*>(cp.get("a"))) == MyValue('x'));
    verify( (*static_cast<MyValue*>(cp.get("b"))) == MyValue('b'));
    verify( (*static_cast<MyValue*>(cp.get("b"))) != MyValue('c'));
    verify(destroyedByMap == 1,"Expect deletion for repeated insertion using same key");
  }

  resetCounts();

  // Test expectations for destruction
  {
    CustomProperties cp;
    cp.add("a", new MyValue(), destroyMyValue);
    cp.add("b", new MyValue(), destroyMyValue);
    cp.add("c", new MyValue(), destroyMyValue);
    verify(destroyedByMap == 0);
  }

  verify(destroyedByMap == 3);

  resetCounts();

  // Test expectations for value removal
  {
    CustomProperties cp;
    cp.add("a", new MyValue('a'), destroyMyValue);
    cp.add("b", new MyValue('b'), destroyMyValue);
    cp.add("c", new MyValue('c'), destroyMyValue);
    cp.remove("a");
    cp.remove("a");
    cp.remove("b");
    verify(destroyedByMap == 2);
  }

  verify(destroyedByMap == 3);

  printf("test_CustomProperty PASSED\n");

  exit(0);
}

