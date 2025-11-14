import React, {useContext, useEffect} from 'react'
import { sidebarDataContext } from '../context/SidebarContext'

const BlockedIp = () => {

  const {sidebarVal, setsidebarVal} = useContext(sidebarDataContext)

  useEffect(() => {
    setsidebarVal("Blocked IP")
  }, [])
  

  return (
    <div className='flex items-center justify-center text-4xl font-semibold h-screen'>Blocked IP</div>
  )
}

export default BlockedIp