import React from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import iconUrl from "leaflet/dist/images/marker-icon.png";
import iconShadow from "leaflet/dist/images/marker-shadow.png";



delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconUrl,
  shadowUrl: iconShadow,
});

export default function ThreatMap() {

  const franceCenter = [46.603354, 1.888334];

  
  const threats = [
    {
      id: 1,
      name: "Paris Breach",
      lat: 48.8566,
      lng: 2.3522,
      severity: "Critical",
    },
    {
      id: 2,
      name: "Lyon Recon",
      lat: 45.764,
      lng: 4.8357,
      severity: "High",
    },
    {
      id: 3,
      name: "Nice Probe",
      lat: 43.7102,
      lng: 7.262,
      severity: "Medium",
    },
    {
      id: 4,
      name: "Bordeaux Scan",
      lat: 44.8378,
      lng: -0.5792,
      severity: "Low",
    },
  ];

  return (
    <div className="h-[600px] w-full rounded-2xl overflow-hidden shadow-lg border border-slate-700">
      <MapContainer
        center={franceCenter}
        zoom={6}
        scrollWheelZoom
        className="h-full w-full"
      >
        <TileLayer
          
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors'
        />

        {threats.map((threat) => (
          <Marker key={threat.id} position={[threat.lat, threat.lng]}>
            <Popup>
              <div className="font-semibold">{threat.name}</div>
              <div>Severity: {threat.severity}</div>
              <div>
                Lat: {threat.lat.toFixed(4)}, Lon: {threat.lng.toFixed(4)}
              </div>
            </Popup>
          </Marker>
        ))}
      </MapContainer>
    </div>
  );
}
