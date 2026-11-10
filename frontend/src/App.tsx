import { BrowserRouter, Route, Routes } from "react-router";
import { QueueView } from "./views/QueueView";
import { IncidentDetailView } from "./views/IncidentDetailView";
import { IngestView } from "./views/IngestView";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<QueueView />} />
        <Route path="/incidents/:incidentId" element={<IncidentDetailView />} />
        <Route path="/ingest" element={<IngestView />} />
        {/* Any other path is a mistyped or stale URL; the queue is the only
            place worth landing. */}
        <Route path="*" element={<QueueView />} />
      </Routes>
    </BrowserRouter>
  );
}
