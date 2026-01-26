import React, {useContext, useEffect} from 'react'
import { sidebarDataContext } from '../context/SidebarContext'

const Events = () => {

    const {eventData, handleDataPanel, setsidebarVal,  sidebarVal} = useContext(sidebarDataContext)

    useEffect(() => {
      setsidebarVal("Events")
    }, [])
    

  return sidebarVal === "Events" && (
   <div className="flex justify-center items-center bg-gray-100 pr-12 pt-6">
      <div className="w-[85%] bg-white shadow-xl rounded-2xl overflow-hidden">
        <table className="w-full border-collapse">
          <thead className="bg-gray-200 sticky top-0">
            <tr>
              <th className="p-3 text-left">Status</th>
              <th className="p-3 text-left">IP</th>
              <th className="p-3 text-left">Time</th>
              <th className="p-3 text-left">Path</th>
              <th className="p-3 text-left">Rule</th>
            </tr>
          </thead>
        </table>
        <div className="max-h-[590px] overflow-y-auto">
          <table className="w-full border-collapse">
            <tbody>
              {eventData.map((item, index) => (
                <tr key={index} onClick={() => { handleDataPanel(item) }} className="border-b hover:bg-gray-100">
                  <td className="p-3">
                    <span
                      className={`inline-block w-4 h-4 rounded-full ${
                        item.severity === "High" ? "bg-red-600" : item.severity === "Low" ? "bg-green-600" : "bg-yellow-200"
                      }`}
                    ></span>
                  </td>
                  <td className="p-3 text-center">{item.ip_address}</td>
                  <td className="p-3">{item.timestamp.split('T')[0]}</td>
                  <td className="p-3 w-12 whitespace-nowrap overflow-x-auto">{item.path}</td>
                  <td className="p-3">{item.rule}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Events