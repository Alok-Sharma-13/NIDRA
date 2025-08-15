import React, { Children, createContext,useState } from 'react'
export let sidebarContext = createContext();

const SidebarContext = ({children}) => {
   const [sidebarVal, setsidebarVal] = useState("HoneyPot");
   let value = {
  sidebarVal, setsidebarVal
}
  return (
    <sidebarContext.Provider value={value}>
        {children}
    </sidebarContext.Provider>
  )
}

export default SidebarContext