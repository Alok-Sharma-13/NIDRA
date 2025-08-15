import React,{useContext} from 'react'
import { sidebarContext } from '../context/SidebarContext'

const Sidebar = ({label}) => {
    const {sidebarVal, setsidebarVal} = useContext(sidebarContext)
  return (
    <div onClick={() => { setsidebarVal(label) }} className={`px-6 py-2 hover:bg-blue-200 rounded-md cursor-pointer ${sidebarVal === label ? 'bg-blue-200': ``} text-md font-semibold`}>{label}</div>
  )
}

export default Sidebar