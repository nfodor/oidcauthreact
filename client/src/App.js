import React from 'react';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import SwaggerUI from 'swagger-ui-react';
import AuthTest from './components/AuthTest';
import 'swagger-ui-react/swagger-ui.css';

function App() {
  return (
    <Router>
      <div className="App">
        <Switch>
          <Route path="/api-docs">
            <SwaggerUI url="http://localhost:5000/api-docs/swagger.json" />
          </Route>
          <Route path="/">
            <AuthTest />
          </Route>
        </Switch>
      </div>
    </Router>
  );
}

export default App;
