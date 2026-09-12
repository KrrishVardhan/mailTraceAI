import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import L from "leaflet";

// Leaflet's default marker icon references image files via relative paths
// that don't resolve correctly under Vite's bundling — rebuild from CDN URLs.
const markerIcon = new L.Icon({
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
});

interface IpLocationMapProps {
  lat: number;
  lon: number;
  label: string;
}

export function IpLocationMap({ lat, lon, label }: IpLocationMapProps) {
  return (
    <MapContainer
      center={[lat, lon]}
      zoom={5}
      scrollWheelZoom={false}
      // height: 100% so it fills whatever flex container wraps it
      style={{ height: "100%", width: "100%", minHeight: "120px", borderRadius: "0px" }}
    >
      <TileLayer
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
      />
      <Marker position={[lat, lon]} icon={markerIcon}>
        <Popup>{label}</Popup>
      </Marker>
    </MapContainer>
  );
}
