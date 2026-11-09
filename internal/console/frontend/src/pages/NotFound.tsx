import { Link } from "react-router-dom";
import { PageHead } from "../components/Layout";

export function NotFound() {
  return (
    <>
      <PageHead title="Page not found" />
      <div className="card card-body">
        <p>
          This console has no page at this address. <Link to="/overview">Go to Overview</Link>.
        </p>
      </div>
    </>
  );
}
