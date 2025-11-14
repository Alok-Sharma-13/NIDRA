import React, {useContext, useEffect} from 'react'

const Rule = () => {

    const {sidebarVal, setsidebarVal} = useContext(sidebarDataContext)
  
    useEffect(() => {
      setsidebarVal("Rule")
    }, [])

  return (
    <div className='flex items-center justify-center text-4xl font-semibold h-screen'>Rule</div>
  )
}

export default Rule