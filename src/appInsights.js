// appInsights.js
import { ApplicationInsights } from "@microsoft/applicationinsights-web";
import { ReactPlugin } from "@microsoft/applicationinsights-react-js";

const reactPlugin = new ReactPlugin();

const appInsights = new ApplicationInsights({
  config: {
    instrumentationKey: "ffbf7e0d-3fca-483f-91a5-7a393331f67c",
    extensions: [reactPlugin],
    extensionConfig: {
      [reactPlugin.identifier]: {},
    },
  },
});

appInsights.loadAppInsights();

export { appInsights, reactPlugin };

