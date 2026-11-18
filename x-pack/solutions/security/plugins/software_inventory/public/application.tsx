/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import ReactDOM from 'react-dom';
import type { AppMountParameters, AppUnmount, CoreStart } from '@kbn/core/public';
import { KibanaContextProvider } from '@kbn/kibana-react-plugin/public';
import { QueryClient, QueryClientProvider } from '@kbn/react-query';
import { PLUGIN_NAME } from '../common/constants';
import { SoftwareInventoryPage } from './pages/software_inventory_page';
import type { SoftwareInventoryStartDependencies } from './types';

interface RenderAppParams {
  coreStart: CoreStart;
  startDeps: SoftwareInventoryStartDependencies;
  params: AppMountParameters;
}

export const renderApp = ({ coreStart, startDeps, params }: RenderAppParams): AppUnmount => {
  coreStart.chrome.docTitle.change(PLUGIN_NAME);
  const queryClient = new QueryClient({
    defaultOptions: { queries: { refetchOnWindowFocus: false, retry: false } },
  });

  ReactDOM.render(
    coreStart.rendering.addContext(
      <KibanaContextProvider services={{ ...coreStart, ...startDeps }}>
        <QueryClientProvider client={queryClient}>
          <SoftwareInventoryPage />
        </QueryClientProvider>
      </KibanaContextProvider>
    ),
    params.element
  );

  return () => {
    ReactDOM.unmountComponentAtNode(params.element);
    queryClient.clear();
  };
};
