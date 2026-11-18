/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiCodeBlock, EuiEmptyPrompt } from '@elastic/eui';
import { i18n } from '@kbn/i18n';

export const SEED_COMMAND =
  'node x-pack/solutions/security/plugins/software_inventory/scripts/seed_demo_data.js';

export const InventoryEmptyState: React.FC = () => (
  <EuiEmptyPrompt
    iconType="package"
    data-test-subj="softwareInventoryEmptyState"
    title={
      <h2>
        {i18n.translate('xpack.softwareInventory.emptyState.title', {
          defaultMessage: 'No software discovered yet',
        })}
      </h2>
    }
    body={
      <>
        <p>
          {i18n.translate('xpack.softwareInventory.emptyState.description', {
            defaultMessage:
              'Software inventory data comes from managed workflows that discover software through osquery, integrations, and logs, then enrich it with CVE and exposure data. Run those workflows, or load demo data with the seed script.',
          })}
        </p>
        <EuiCodeBlock isCopyable paddingSize="s" language="bash">
          {SEED_COMMAND}
        </EuiCodeBlock>
      </>
    }
  />
);
