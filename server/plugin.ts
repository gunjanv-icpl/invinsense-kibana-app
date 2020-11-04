/*
 * Licensed to Elasticsearch B.V. under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch B.V. licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import {
  CoreSetup,
  CoreStart,
  Logger,
  Plugin,
  PluginInitializerContext,
} from 'kibana/server';

import { WazuhPluginSetup, WazuhPluginStart } from './types';
import { setupRoutes } from './routes';
interface LegacySetup {
  server: any
}

export class WazuhPlugin implements Plugin<WazuhPluginSetup, WazuhPluginStart> {
  private readonly logger: Logger;

  constructor(private readonly initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
  }
  
  public setup(core: CoreSetup, plugins: WazuhPluginSetup) {
    this.logger.debug('Wazuh-wui: Setup');

    // TODO: implement router
    const router = core.http.createRouter();
    setupRoutes(router);
    // TODO: implement Wazuh monitoring

    // TODO: implement Scheduler handler 
    
    return {};
  }

  public start(core: CoreStart) {
    return {};
  }

  public stop() { }
}
