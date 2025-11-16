import React,{useContext} from 'react'
import { sidebarDataContext } from '../context/SidebarContext'

const Sidebar = ({label, eventHandler}) => {
    const {sidebarVal, setsidebarVal} = useContext(sidebarDataContext)
  return (
    <div onClick={() => { setsidebarVal(label);  eventHandler() }} className={`px-6 py-2 text-xl hover:bg-blue-200 rounded-md cursor-pointer ${sidebarVal === label ? 'bg-blue-200': ``} text-md font-semibold`}>{label}</div>
  )
}

export default Sidebar