import React, { useContext, useEffect } from 'react'
import { sidebarDataContext } from '../context/SidebarContext'

const High = () => {
  const {sidebarVal, setsidebarVal} = useContext(sidebarDataContext)

  useEffect(() => {
    setsidebarVal("High")
  }, [])

  return (
    <div className='flex items-center justify-center text-4xl font-semibold h-screen'>High</div>
  )
}

export default High