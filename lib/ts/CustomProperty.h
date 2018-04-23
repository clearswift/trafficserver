/** @file

  A map for storing void* values keyed on a name string.

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

  CustomProperty.h

  This file implements a simple map for storing property values keyed on a
  name string.

  The map assumes ownership of stored property values.

  Because the value can be of any type (void*), storage of a value also
  requires storage of a pointer to a function that the map can use in order
  to destroy the value.

  When the map is destroyed, remaining property values are destroyed.

 ****************************************************************************/
#ifndef CUSTOM_PROPERTY_H
#define CUSTOM_PROPERTY_H

#include <map>
#include <memory>
#include <string>

//
//    CustomProperties map
//
class CustomProperties
{
public:
  CustomProperties();
  CustomProperties(const CustomProperties&) = delete;
  CustomProperties operator=(const CustomProperties&) = delete;
  void add(const char *name, void *value, void(*destroyValue)(void*));
  void remove(const char *name);
  void* get(const char *name);
  void clear();
private:

  typedef std::unique_ptr<void, void(*)(void*)> PropertyValue;

  std::unique_ptr<std::map<std::string, PropertyValue>> m_properties;
};

#endif
