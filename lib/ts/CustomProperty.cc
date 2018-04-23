#include "CustomProperty.h"

CustomProperties::CustomProperties()
  : m_properties(new std::map<std::string, PropertyValue>())
{
  /**
    Should not be necessary to dynamically allocate storage for
    this map, but, if not dynamically allocated, then
    insertions got segmentation faults:
      Thread #4 [[ET_NET 1]] 28415 [core: 1] (Suspended : Signal : SIGSEGV:Segmentation fault)
        std::_Rb_tree_decrement() at 0x3591869eca
        std::_Rb_tree_iterator<std::pair<std::string const, CustomProperties::PropertyValue> >::operator--() at stl_tree.h:224 0x2b6f90fd7471
        std::_Rb_tree<std::string, std::pair<std::string const, CustomProperties::PropertyValue>, std::_Select1st<std::pair<std::string const, CustomProperties::PropertyValue> >, std::less<std::string>, std::allocator<std::pair<std::string const, CustomProperties::PropertyValue> > >::_M_get_insert_unique_pos() at stl_tree.h:1,845 0x2b6f90fd6f97
        std::_Rb_tree<std::string, std::pair<std::string const, CustomProperties::PropertyValue>, std::_Select1st<std::pair<std::string const, CustomProperties::PropertyValue> >, std::less<std::string>, std::allocator<std::pair<std::string const, CustomProperties::PropertyValue> > >::_M_insert_unique<std::pair<char const*, CustomProperties::PropertyValue> >() at stl_tree.h:1,889 0x2b6f90fd6b14
        std::map<std::string, CustomProperties::PropertyValue, std::less<std::string>, std::allocator<std::pair<std::string const, CustomProperties::PropertyValue> > >::insert<std::pair<char const*, CustomProperties::PropertyValue>, void>() at stl_map.h:740 0x2b6f90fd68a8
        CustomProperties::add() at CustomProperty.cc:36 0x2b6f90fd645b
        NetVConnection::addCustomProperty() at I_NetVConnection.h:558 0x546978
  */
}

void CustomProperties::add(const char *name, void *value, void(*destroyValue)(void*))
{
  remove(name);
  m_properties->emplace(std::make_pair(name, PropertyValue{value, destroyValue}));
}

void CustomProperties::remove(const char *name)
{
  auto i = m_properties->find(name);
  if ( i != m_properties->end())
  {
    m_properties->erase(i);
  }
}

void* CustomProperties::get(const char *name)
{ 
  auto i = m_properties->find(name);
  return i == m_properties->end() ? nullptr : i->second.get();
}

void CustomProperties::clear()
{
  m_properties->clear();
}
