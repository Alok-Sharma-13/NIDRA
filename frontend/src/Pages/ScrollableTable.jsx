import React, { useContext } from "react";
import {sidebarDataContext} from "../context/SidebarContext";

    // const data = [
    // { status: "black", ip: "127.0.0.1", time: "12:30", path: "/v1", country: "India" },
    // { status: "red", ip: "127.0.0.1", time: "1:30", path: "/api", country: "China" },
    // { status: "black", ip: "127.0.0.2", time: "2:00", path: "/cont", country: "Pakistan" },
    // { status: "red", ip: "8.8.8.8", time: "3:00", path: "/car", country: "Pakistan" },
    // { status: "red", ip: "1.1.2.3", time: "4:00", path: "/admin", country: "Pakistan" },
    // { status: "black", ip: "1.1.1.1", time: "5:00", path: "/p1", country: "France" },
    // { status: "black", ip: "27.0.0.1", time: "6:00", path: "/c2", country: "Indonesia" },
    // { status: "red", ip: "127.0.0.1", time: "1:30", path: "/api", country: "China" },
    // { status: "black", ip: "127.0.0.2", time: "2:00", path: "/cont", country: "Pakistan" },
    // { status: "red", ip: "8.8.8.8", time: "3:00", path: "/car", country: "Pakistan" },
    // { status: "red", ip: "1.1.2.3", time: "4:00", path: "/admin", country: "Pakistan" },
    // { status: "black", ip: "1.1.1.1", time: "5:00", path: "/p1", country: "France" },
    // { status: "black", ip: "27.0.0.1", time: "6:00", path: "/c2", country: "Indonesia" },
    // ];

export default function ScrollableTable() {

    const { handleDataPanel , alltraficData} = useContext(sidebarDataContext)

  return (
    <div className="flex justify-center items-center min-h-screen bg-gray-100 p-6">
      <div className="w-[92%] bg-white shadow-xl rounded-2xl overflow-hidden">
        <table className="w-full border-collapse">
          <thead className="bg-gray-200 sticky top-0">
            <tr>
              <th className="p-3 text-left">Status</th>
              <th className="p-3 text-left">IP</th>
              <th className="p-3 text-left">Time</th>
              <th className="p-3 text-left">Path</th>
              <th className="p-3 text-left">Country</th>
            </tr>
          </thead>
        </table>
        <div className="max-h-[600px] overflow-y-auto">
          <table className="w-full border-collapse">
            <tbody>
              {alltraficData.map((item, index) => (
                <tr key={index} onClick={handleDataPanel} className="border-b hover:bg-gray-100">
                  <td className="p-3">
                    <span
                      className={`inline-block w-4 h-4 rounded-full ${
                        item.status === "red" ? "bg-red-600" : "bg-black"
                      }`}
                    ></span>
                  </td>
                  <td className="p-3 text-center">{item.ip_address}</td>
                  <td className="p-3">{item.timestamp.split('T')[0]}</td>
                  <td className="p-3">{item.path}</td>
                  <td className="p-3">{item.country}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
