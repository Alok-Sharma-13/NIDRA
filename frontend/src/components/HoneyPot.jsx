import React from 'react'

const HoneyPot = () => {
    return (
        <div className='w-full h-full flex justify-center items-start p-3'>
            <div className=' w-[60%] flex flex-col gap-13 p-5'>
                <h1 className='text-4xl text-center font-semibold mb-2'>Honeypot</h1>
                <div className='flex gap-3 text-2xl'>
                    URL: <input type="text" className='border flex-2 border-gray-500 px-3 py-2 outline-none rounded-md text-sm' />
                </div>
                <div className='flex gap-3 text-2xl'>
                    Security: <input type="text" className='border flex-2 border-gray-500 px-3 py-2 outline-none rounded-md text-sm' />
                </div>
                <div className='flex gap-3 justify-between'>
                    <button className='flex-1 text-white bg-blue-500 rounded-md'>Same</button>
                    <button className='flex-1 py-2 bg-red-500 rounded-md'>Delete</button>
                </div>
                <div className='flex items-center justify-center'>
                    <button className='flex-1 font-semibold py-3 text-amber-100 bg-gray-400 rounded-md'>Previous Honeypots</button>
                </div>
            </div>
        </div>
    )
}

export default HoneyPot