import React, { useState, useContext, useEffect } from 'react'
import { sidebarDataContext } from '../context/SidebarContext';

const data = [
  { status: "black", ip: "127.0.0.1", time: "12:30", path: "/v1", country: "India" },
  { status: "red", ip: "127.0.0.1", time: "1:30", path: "/api", country: "China" },
  { status: "black", ip: "127.0.0.2", time: "2:00", path: "/cont", country: "Pakistan" },
  { status: "red", ip: "8.8.8.8", time: "3:00", path: "/car", country: "Pakistan" },
  { status: "red", ip: "1.1.2.3", time: "4:00", path: "/admin", country: "Pakistan" },
  { status: "black", ip: "1.1.1.1", time: "5:00", path: "/p1", country: "France" },
  { status: "black", ip: "27.0.0.1", time: "6:00", path: "/c2", country: "Indonesia" },
  { status: "red", ip: "127.0.0.1", time: "1:30", path: "/api", country: "China" },
  { status: "black", ip: "127.0.0.2", time: "2:00", path: "/cont", country: "Pakistan" },
  { status: "red", ip: "8.8.8.8", time: "3:00", path: "/car", country: "Pakistan" },
  { status: "red", ip: "1.1.2.3", time: "4:00", path: "/admin", country: "Pakistan" },
  { status: "black", ip: "1.1.1.1", time: "5:00", path: "/p1", country: "France" },
  { status: "black", ip: "27.0.0.1", time: "6:00", path: "/c2", country: "Indonesia" },
];

const Country = () => {
  const [selectedCountry, setSelectedCountry] = useState("");
  const {sidebarVal, setsidebarVal} = useContext(sidebarDataContext)
  const [allCountry, setallCountry] = useState(data)
  const [filteredCountry, setfilteredCountry] = useState(data || [])

  const countries = ["India", "China", "Pakistan", "France", "Indonesia"];

  useEffect(() => {
    setsidebarVal("country")
    handleCountry()
  
  }, [selectedCountry])
  

   const handleCountry = () => {
      if(selectedCountry){
       const country = allCountry.filter((item)=> item.country === selectedCountry)
      //  console.log(country)
       setfilteredCountry(country)         
      } else {
        setfilteredCountry(allCountry)
      }
   }

  return (
    // <div className='flex items-center justify-center text-4xl font-semibold h-screen'>Country</div>
   sidebarVal === "country" && <div className="flex justify-center items-center min-h-screen bg-gray-100 p-2">
      <div className="w-[80%] bg-white border border-gray-300 rounded-xl shadow-md overflow-hidden">
        <table className="w-full border-collapse">
          <thead className="bg-blue-900 text-white">
            <tr>
              <th className="p-3 text-left w-1/2">Country</th>
              <th className="p-3 text-left">
                <select
                  value={selectedCountry}
                  onChange={(e) => { setSelectedCountry(e.target.value); handleCountry(e); }}
                  className="border border-gray-400 rounded-md px-3 py-1 text-white focus:outline-none"
                >
                  <option value="" className='text-black'>All</option>
                  {countries.map((country, index) => (
                    <option key={index} className='text-black' value={country}>
                      {country}
                    </option>
                  ))}
                </select>
              </th>
            </tr>
          </thead>

          {/* <tbody className='overflow-y-auto max-h-64'>
            {Array(5)
              .fill("")
              .map((_, index) => (
                <tr key={index} className="border-t h-12">
                  <td colSpan="2">aditya yafaghd</td>
                </tr>
              ))}
          </tbody> */}
        </table>
        <div className="max-h-[600px] overflow-y-auto">
          <table className="w-full border-collapse">
            <tbody>
              {filteredCountry.map((item, index) => (
                <tr key={index} className="border-b hover:bg-gray-100">
                  <td className="p-3">
                    <span
                      className={`inline-block w-4 h-4 rounded-full ${item.status === "red" ? "bg-red-600" : "bg-black"
                        }`}
                    ></span>
                  </td>
                  <td className="p-3 text-center">{item.ip}</td>
                  <td className="p-3">{item.time}</td>
                  <td className="p-3">{item.path}</td>
                  <td className="p-3">{item.country}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </div>
    </div>
  )
}

export default Country