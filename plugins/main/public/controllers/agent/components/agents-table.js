/*
 * Wazuh app - React component for building the agents table.
 *
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

import React, { Component } from 'react';
import PropTypes from 'prop-types';
import {
  EuiButton,
  EuiButtonIcon,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiToolTip,
  EuiIconTip,
  EuiCheckbox,
  EuiConfirmModal,
  EuiTextArea,
  EuiHealth,
} from '@elastic/eui';
import { AppNavigate } from '../../../react-services/app-navigate';
import { GroupTruncate } from '../../../components/common/util';
import { WzButtonPermissions } from '../../../components/common/permissions/button';
import { formatUIDate } from '../../../react-services/time-service';
import { withErrorBoundary } from '../../../components/common/hocs';
import {
  API_NAME_AGENT_STATUS,
  UI_ORDER_AGENT_STATUS,
  AGENT_SYNCED_STATUS,
  SEARCH_BAR_WQL_VALUE_SUGGESTIONS_COUNT,
} from '../../../../common/constants';
import { AgentStatus } from '../../../components/agents/agent-status';
import { AgentSynced } from '../../../components/agents/agent-synced';
import { TableWzAPI } from '../../../components/common/tables';
import { WzRequest } from '../../../react-services/wz-request';
import { get as getLodash } from 'lodash';
import { getToasts } from '../../../kibana-services';

const searchBarWQLOptions = {
  implicitQuery: {
    query: 'id!=000',
    conjunction: ';',
  },
};

export const AgentsTable = withErrorBoundary(
  class AgentsTable extends Component {
    _isMount = false;

    constructor(props) {
      super(props);
      this.state = {
        filters: {
          default: { q: 'id!=000' },
          ...(sessionStorage.getItem('wz-agents-overview-table-filter')
            ? JSON.parse(sessionStorage.getItem('wz-agents-overview-table-filter'))
            : {}),
        },
        reloadTable: 0,
        allChecked: false,
        allChecked1: true,
        isChecked: [],
        agents: this.props.affected_items,
        isBlockDomainModelVisible: false,
        blockDomainTextArea: '',
        isDeleteAgentModalVisible: false,
        deleteAgentDetails: {},
        isRestartAgentModalVisible: false,
        restartAgentDetails: {},
      };
    }
    async componentDidMount() {
      this._isMount = true;
    }

    componentWillUnmount() {
      this._isMount = false;
      if (sessionStorage.getItem('wz-agents-overview-table-filter')) {
        sessionStorage.removeItem('wz-agents-overview-table-filter');
      }
    }

    async reloadAgents() {
      this.setState({ reloadTable: Date.now() });
      await this.props.reload();
    }
    //todo: add checkboxes here
    async handleAllCheck() {
      if (this.state.allChecked) {
        this.setState({ allChecked: false, isChecked: [] });
        return;
      }
      this.setState({ allChecked: true, isChecked: this.state.agents.map((data) => data.id) });
      this.isAllChecked();
      return;
    }

    async handleSingleCheck(e) {
      const { id } = e.target;
      if (this.state.isChecked.includes(id)) {
        this.setState({
          allChecked: false,
          isChecked: this.state.isChecked.filter((checked_name) => checked_name !== id),
        });
        return;
      }
      this.state.isChecked.push(id);
      this.setState({ allChecked: this.state.isChecked.length === this.state.agents.length });
    }

    async componentDidUpdate(prevProps) {
      if (
        // TODO: external filters
        !_.isEqual(prevProps.filters, this.props.filters)
      ) {
        this.setState({ filters: this.props.filters });
      }
    }

    showToast = (color, title, text, time) => {
      getToasts().add({
        color: color,
        title: title,
        text: text,
        toastLifeTimeMs: time,
      });
    };

    actionButtonsRender(agent) {
      return (
        <div className={'icon-box-action'}>
          <EuiToolTip content="Open summary panel for this agent" position="left">
            <EuiButtonIcon
              onClick={(ev) => {
                ev.stopPropagation();
                AppNavigate.navigateToModule(ev, 'agents', {
                  tab: 'welcome',
                  agent: agent.id,
                });
              }}
              iconType="eye"
              color={'primary'}
              aria-label="Open summary panel for this agent"
            />
          </EuiToolTip>
          &nbsp;
          {agent.status !== API_NAME_AGENT_STATUS.NEVER_CONNECTED && (
            <EuiToolTip content="Open configuration for this agent" position="left">
              <EuiButtonIcon
                onClick={(ev) => {
                  ev.stopPropagation();
                  AppNavigate.navigateToModule(ev, 'agents', {
                    tab: 'configuration',
                    agent: agent.id,
                  });
                }}
                color={'primary'}
                iconType="wrench"
                aria-label="Open configuration for this agent"
              />
            </EuiToolTip>
          )}
          {/* &nbsp;
          <EuiToolTip position="top" content={<p>Restart Agent</p>}>
            <EuiButtonIcon
              iconType="refresh"
              isDisabled={agent.status !== 'active' ? true : false}
              aria-label="restart"
              onClick={() => {
                this.setIsRestartAgentModalVisible(true, agent);
              }}
            ></EuiButtonIcon>
          </EuiToolTip> */}
          &nbsp;
          <EuiToolTip position="top" content={<p>Restart Agent</p>}>
            <EuiButtonIcon
              iconType="refresh"
              isDisabled={agent.agentStatus != 'active' ? true : false}
              aria-label="restart"
              onClick={() => {
                this.setIsRestartAgentModalVisible(true, agent);
              }}
            ></EuiButtonIcon>
          </EuiToolTip>
          &nbsp;
          <EuiToolTip position="top" content={<p>Delete Agent</p>}>
            <EuiButtonIcon
              iconType="trash"
              color="danger"
              aria-label="Delete"
              onClick={() => {
                this.setIsDeleteAgentModalVisible(true, agent);
              }}
            ></EuiButtonIcon>
          </EuiToolTip>
        </div>
      );
    }

    addIconPlatformRender(agent) {
      let icon = '';
      const os = agent?.os || {};

      if ((os?.uname || '').includes('Linux')) {
        icon = 'linux';
      } else if (os?.platform === 'windows') {
        icon = 'windows';
      } else if (os?.platform === 'darwin') {
        icon = 'apple';
      }
      const os_name = `${agent?.os?.name || ''} ${agent?.os?.version || ''}`;

      return (
        <EuiFlexGroup gutterSize="xs">
          <EuiFlexItem grow={false}>
            <i
              className={`fa fa-${icon} AgentsTable__soBadge AgentsTable__soBadge--${icon}`}
              aria-hidden="true"
            ></i>
          </EuiFlexItem>{' '}
          <EuiFlexItem>{os_name.trim() || '-'}</EuiFlexItem>
        </EuiFlexGroup>
      );
    }

    async assignGroup(groupName) {
      const selectedAgents = this.state.agents
        .filter((agent) => this.state.isChecked.includes(agent.id))
        .map((agent) => {
          return agent;
        });
      const hasNotWindowsAgent = selectedAgents.filter(
        (element) => element.os && element.os.platform !== 'windows'
      );
      const hasWindowAgent = selectedAgents.filter(
        (element) => element.os && element.os.platform === 'windows'
      );

      if (this.state.isChecked.length == 0) {
        this.showToast('warning', 'Warning', 'Please select at least one agent', 3000);
        return;
      } else if (hasNotWindowsAgent.length > 0) {
        const otherAgentsName = hasNotWindowsAgent.map((element) => element.name).join(',');
        this.showToast(
          'warning',
          'Warning',
          'We are not perform ' +
            groupName +
            ' in ' +
            otherAgentsName +
            ' agents, which is are not windows agents.',
          3000
        );
      }
      if (hasWindowAgent.length > 0) {
        const windowsAgentsId = hasWindowAgent.map((element) => element.id).join(',');
        const response = await WzRequest.apiReq(
          'PUT',
          `/agents/group?pretty=false&wait_for_complete=false&group_id=${groupName}&agents_list=${windowsAgentsId}`,
          {}
        );
        this.showToast('success', 'Success', response?.data.message, 3000);
        this.reloadAgents();
      }
    }

    async blockDomains(agentIds, domainList) {
      const selectedAgents = this.state.agents
        .filter((agent) => this.state.isChecked.includes(agent.id))
        .map((agent) => {
          return agent;
        });
      const hasNotWindowsAgent = selectedAgents.filter(
        (element) => element.os && element.os.platform !== 'windows'
      );
      const hasWindowAgent = selectedAgents.filter(
        (element) => element.os && element.os.platform === 'windows'
      );

      if (this.state.isChecked.length == 0) {
        this.showToast('warning', 'Warning', 'Please select at least one agent', 3000);
        return;
      } else if (hasNotWindowsAgent.length > 0) {
        const otherAgentsName = hasNotWindowsAgent.map((element) => element.name).join(',');
        this.showToast(
          'warning',
          'Warning',
          'We are not perform block domains in ' +
            otherAgentsName +
            ' agents, which is are not windows agents.',
          3000
        );
      }

      const body = {
        command: 'block-domain0',
        custom: false,
        alert: { data: { domains: domainList } },
        devTools: true,
      };
      if (hasWindowAgent.length > 0) {
        const windowsAgentsId = hasWindowAgent.map((element) => element.id).join(',');
        const response = await WzRequest.apiReq(
          'PUT',
          `/active-response?agents_list=${windowsAgentsId}`,
          body
        );
        this.showToast('success', 'Success', response?.data.message, 3000);
      }
    }

    async blockUSB() {
      const selectedAgents = this.state.agents
        .filter((agent) => this.state.isChecked.includes(agent.id))
        .map((agent) => {
          return agent;
        });
      const hasNotWindowsAgent = selectedAgents.filter(
        (element) => element.os && element.os.platform !== 'windows'
      );
      const hasWindowAgent = selectedAgents.filter(
        (element) => element.os && element.os.platform === 'windows'
      );

      if (this.state.isChecked.length == 0) {
        this.showToast('warning', 'Warning', 'Please select at least one agent', 3000);
        return;
      } else if (hasNotWindowsAgent.length > 0) {
        const otherAgentsName = hasNotWindowsAgent.map((element) => element.name).join(', ');
        this.showToast(
          'warning',
          'Warning',
          'We are not perform block usb in ' +
            otherAgentsName +
            ' agents, which is are not windows agents.',
          3000
        );
      }
      if (hasWindowAgent.length > 0) {
        const body = {
          command: 'blockusb0',
          custom: false,
          alert: { data: {} },
          devTools: true,
        };

        const windowsAgentsId = hasWindowAgent.map((element) => element.id).join(',');
        const response = await WzRequest.apiReq(
          'PUT',
          `/active-response?agents_list=${windowsAgentsId}`,
          body
        );

        this.showToast('success', 'Success', response?.data.message, 3000);
      }
    }

    async unBlockUSB() {
      const selectedAgents = this.state.agents
        .filter((agent) => this.state.isChecked.includes(agent.id))
        .map((agent) => {
          return agent;
        });
      const hasNotWindowsAgent = selectedAgents.filter(
        (element) => element.os && element.os.platform !== 'windows'
      );
      const hasWindowAgent = selectedAgents.filter(
        (element) => element.os && element.os.platform === 'windows'
      );

      if (this.state.isChecked.length == 0) {
        this.showToast('warning', 'Warning', 'Please select at least one agent', 3000);
        return;
      } else if (hasNotWindowsAgent.length > 0) {
        const otherAgentsName = hasNotWindowsAgent.map((element) => element.name).join(', ');
        this.showToast(
          'warning',
          'Warning',
          'We are not perform block usb in ' +
            otherAgentsName +
            ' agents, which is are not windows agents.',
          3000
        );
      }
      if (hasWindowAgent.length > 0) {
        const body = {
          command: 'unblockusb0',
          custom: false,
          alert: { data: {} },
          devTools: true,
        };
        const windowsAgentsId = hasWindowAgent.map((element) => element.id).join(',');
        const response = await WzRequest.apiReq(
          'PUT',
          `/active-response?agents_list=${windowsAgentsId}`,
          body
        );
        this.showToast('success', 'Success', response?.data.message, 3000);
      }
    }

    async isAllChecked() {
      return this.state.allChecked;
    }

    async onConfirmClick() {
      const textAreaValue = this.state.blockDomainTextArea;

      if (this.state.isChecked.length == 0 || textAreaValue == '') {
        if (this.state.isChecked.length == 0) {
          this.showToast('warning', 'Warning', 'Please select at least one agent', 3000);
          return;
        } else {
          this.showToast('warning', 'Warning', 'Please enter domain vaule', 3000);
          return;
        }
      }
      const splitDomains = textAreaValue
        .split(',')
        .map((domain) => domain.trim())
        .filter(Boolean);

      this.setIsBlockDomainModalVisible(false);
      var agentIds = this.state.isChecked.join(',');
      var scanRes = await this.blockDomains(agentIds, splitDomains);
      console.log('scnResBlockDomain', scanRes);
    }

    async onDeleteConfirmClick() {
      this.setIsDeleteAgentModalVisible(false);
      this.deleteAgent();
    }

    async deleteAgent() {
      const body = {
        devTools: true,
        id: 'default',
      };
      const response = await WzRequest.apiReq(
        'DELETE',
        `/agents?pretty=true&older_than=0s&agents_list=${this.state.deleteAgentDetails.id}&status=all`,
        body
      );
      this.showToast('success', 'Success', response?.data.message, 3000);
      this.reloadAgents();
    }

    async onRestartConfirmClick() {
      this.setIsRestartAgentModalVisible(false);
      this.restartAgent();
    }

    async restartAgent() {
      const body = {
        devTools: true,
        id: 'default',
      };
      const response = await WzRequest.apiReq(
        'PUT',
        `/agents/${this.state.restartAgentDetails.id}/restart`,
        body
      );
      this.showToast('success', 'Success', response?.data.message, 3000);
      this.reloadAgents();
    }

    // Columns with the property truncateText: true won't wrap the text
    // This is added to prevent the wrap because of the table-layout: auto
    defaultColumns = [
      {
        field: 'id',
        name: (
          <>
            {/* <EuiCheckbox
              id='all'
              key='all'
              onChange={this.handleAllCheck.bind(this)}
              checked={this.state?.isChecked.length == this.state?.agents.length} /> */}
            <a onClick={this.handleAllCheck.bind(this)}>Select All</a>
          </>
        ),
        truncateText: false,
        mobileOptions: {
          show: false,
        },
        sortable: false,
        render: (agentId) => {
          return (
            <EuiCheckbox
              id={agentId}
              key={agentId}
              checked={this.state.isChecked.includes(agentId)}
              onChange={this.handleSingleCheck.bind(this)}
            />
          );
        },
      },
      {
        field: 'id',
        name: 'ID',
        sortable: true,
        show: true,
        searchable: true,
      },
      {
        field: 'name',
        name: 'Name',
        sortable: true,
        show: true,
        searchable: true,
      },
      {
        field: 'ip',
        name: 'IP address',
        sortable: true,
        show: true,
        searchable: true,
      },
      {
        field: 'group',
        name: 'Group(s)',
        sortable: true,
        show: true,
        render: (groups) => (groups !== '-' ? this.renderGroups(groups) : '-'),
        searchable: true,
      },
      {
        field: 'os.name,os.version',
        composeField: ['os.name', 'os.version'],
        name: 'Operating system',
        sortable: true,
        show: true,
        render: (field, agentData) => this.addIconPlatformRender(agentData),
        searchable: true,
      },
      {
        field: 'group',
        name: 'Isolation Status',
        truncateText: true,
        render: (groups) => this.renderIsolationStatus(groups),
        sortable: false,
      },
      {
        field: 'node_name',
        name: 'Cluster node',
        sortable: true,
        show: true,
        searchable: true,
      },
      {
        field: 'version',
        name: 'Version',
        sortable: true,
        show: true,
        searchable: true,
      },
      {
        field: 'dateAdd',
        name: (
          <span>
            Registration date{' '}
            <EuiIconTip
              content="This is not searchable through a search term."
              size="s"
              color="subdued"
              type="alert"
            />
          </span>
        ),
        sortable: true,
        show: false,
        searchable: false,
      },
      {
        field: 'lastKeepAlive',
        name: (
          <span>
            Last keep alive{' '}
            <EuiIconTip
              content="This is not searchable through a search term."
              size="s"
              color="subdued"
              type="alert"
            />
          </span>
        ),
        sortable: true,
        show: false,
        searchable: false,
      },
      {
        field: 'status',
        name: 'Status',
        truncateText: true,
        sortable: true,
        show: true,
        render: (status, agent) => <AgentStatus status={status} agent={agent} />,
      },
      {
        field: 'group_config_status',
        name: 'Synced',
        sortable: true,
        show: false,
        render: (synced) => <AgentSynced synced={synced} />,
        searchable: true,
      },
      {
        align: 'right',
        width: '5%',
        field: 'actions',
        name: 'Actions',
        show: true,
        render: (field, agentData) => this.actionButtonsRender(agentData),
        searchable: false,
      },
    ];

    setAgents(data) {
      this.setState({ agents: data });
    }

    setIsBlockDomainModalVisible(enable) {
      this.setState({ isBlockDomainModelVisible: enable });
    }

    setIsDeleteAgentModalVisible(enable, agent) {
      this.setState({ deleteAgentDetails: agent });
      this.setState({ isDeleteAgentModalVisible: enable });
    }

    setIsRestartAgentModalVisible(enable, agent) {
      this.setState({ restartAgentDetails: agent });
      this.setState({ isRestartAgentModalVisible: enable });
    }

    tableRender() {
      const getRowProps = (item) => {
        const { id } = item;
        return {
          'data-test-subj': `row-${id}`,
          className: 'customRowClass',
          onClick: () => {},
        };
      };

      const getCellProps = (item, column) => {
        if (column.field == 'actions' || column.field == 'id') {
          return;
        }
        return {
          onClick: (ev) => {
            AppNavigate.navigateToModule(ev, 'agents', {
              tab: 'welcome',
              agent: item.id,
            });
            ev.stopPropagation();
          },
        };
      };

      // The EuiBasicTable tableLayout is set to "auto" to improve the use of empty space in the component.
      // Previously the tableLayout is set to "fixed" with percentage width for each column, but the use of space was not optimal.
      // Important: If all the columns have the truncateText property set to true, the table cannot adjust properly when the viewport size is small.
      return (
        <EuiFlexGroup className="wz-overflow-auto">
          <EuiFlexItem>
            <TableWzAPI
              title="Agents"
              actionButtons={[
                <WzButtonPermissions
                  buttonType="empty"
                  permissions={[{ action: 'agent:create', resource: '*:*:*' }]}
                  iconType="plusInCircle"
                  onClick={() => this.props.addingNewAgent()}
                >
                  Deploy new agent
                </WzButtonPermissions>,
              ]}
              endpoint="/agents"
              tableColumns={this.defaultColumns}
              tableInitialSortingField="id"
              tablePageSizeOptions={[10, 25, 50, 100]}
              reload={this.state.reloadTable}
              mapResponseItem={(item) => {
                return {
                  ...item,
                  ...(item.ip ? { ip: item.ip } : { ip: '-' }),
                  ...(typeof item.dateAdd === 'string'
                    ? { dateAdd: formatUIDate(item.dateAdd) }
                    : { dateAdd: '-' }),
                  ...(typeof item.lastKeepAlive === 'string'
                    ? { lastKeepAlive: formatUIDate(item.lastKeepAlive) }
                    : { lastKeepAlive: '-' }),
                  ...(item.node_name !== 'unknown'
                    ? { node_name: item.node_name }
                    : { node_name: '-' }),
                  /*
                  The agent version contains the Wazuh word, this gets the string starting with
                  v<NUMBER><ANYTHING>
                  */
                  ...(typeof item.version === 'string'
                    ? { version: item.version.match(/(v\d.+)/)?.[1] }
                    : { version: '-' }),
                };
              }}
              rowProps={getRowProps}
              filters={this.state.filters}
              downloadCsv
              showReload
              showFieldSelector
              searchTable
              searchBarWQL={{
                options: searchBarWQLOptions,
                suggestions: {
                  field(currentValue) {
                    return [
                      {
                        label: 'dateAdd',
                        description: 'filter by registration date',
                      },
                      { label: 'id', description: 'filter by id' },
                      { label: 'ip', description: 'filter by IP address' },
                      { label: 'group', description: 'filter by group' },
                      {
                        label: 'group_config_status',
                        description: 'filter by group configuration status',
                      },
                      {
                        label: 'lastKeepAlive',
                        description: 'filter by last keep alive',
                      },
                      { label: 'manager', description: 'filter by manager' },
                      { label: 'name', description: 'filter by name' },
                      {
                        label: 'node_name',
                        description: 'filter by cluster name',
                      },
                      {
                        label: 'os.name',
                        description: 'filter by operating system name',
                      },
                      {
                        label: 'os.platform',
                        description: 'filter by operating platform',
                      },
                      {
                        label: 'os.version',
                        description: 'filter by operating system version',
                      },
                      { label: 'status', description: 'filter by status' },
                      { label: 'version', description: 'filter by version' },
                    ];
                  },
                  value: async (currentValue, { field }) => {
                    try {
                      switch (field) {
                        case 'status':
                          return UI_ORDER_AGENT_STATUS.map((status) => ({
                            label: status,
                          }));
                        case 'group_config_status':
                          return [AGENT_SYNCED_STATUS.SYNCED, AGENT_SYNCED_STATUS.NOT_SYNCED].map(
                            (label) => ({
                              label,
                            })
                          );
                        default: {
                          const response = await WzRequest.apiReq('GET', '/agents', {
                            params: {
                              distinct: true,
                              limit: SEARCH_BAR_WQL_VALUE_SUGGESTIONS_COUNT,
                              select: field,
                              sort: `+${field}`,
                              ...(currentValue
                                ? {
                                    q: `${searchBarWQLOptions.implicitQuery.query}${searchBarWQLOptions.implicitQuery.conjunction}${field}~${currentValue}`,
                                  }
                                : {
                                    q: `${searchBarWQLOptions.implicitQuery.query}`,
                                  }),
                            },
                          });
                          if (field === 'group') {
                            /* the group field is returned as an string[],
                            example: ['group1', 'group2']
     
                            Due the API request done to get the distinct values for the groups is
                            not returning the exepected values, as workaround, the values are
                            extracted in the frontend using the returned results.
     
                            This API request to get the distint values of groups doesn't
                            return the unique values for the groups, else the unique combination
                            of groups.
                            */
                            return response?.data?.data.affected_items
                              .map((item) => getLodash(item, field))
                              .flat()
                              .filter((item, index, array) => array.indexOf(item) === index)
                              .sort()
                              .map((group) => ({ label: group }));
                          }

                          const agentsData = response?.data?.data.affected_items.map((item) => ({
                            label: getLodash(item, field),
                          }));

                          this.setState({ agents: agentsData, allChecked: false, isChecked: [] });
                          return agentsData;
                        }
                      }
                    } catch (error) {
                      return [];
                    }
                  },
                },
                validate: {
                  value: ({ formattedValue, value: rawValue }, { field }) => {
                    const value = formattedValue ?? rawValue;
                    if (value) {
                      if (['dateAdd', 'lastKeepAlive'].includes(field)) {
                        return /^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}:\d{2}(.\d{1,6})?Z?)?$/.test(
                          value
                        )
                          ? undefined
                          : `"${value}" is not a expected format. Valid formats: YYYY-MM-DD, YYYY-MM-DD HH:mm:ss, YYYY-MM-DDTHH:mm:ss, YYYY-MM-DDTHH:mm:ssZ.`;
                      }
                    }
                  },
                },
              }}
              searchBarProps={{
                buttonsRender: () => (
                  <EuiButton
                    iconType="refresh"
                    fill={true}
                    onClick={() => {
                      this.setState({ allChecked: false, isChecked: [] });
                      this.reloadAgents();
                    }}
                  >
                    Refresh
                  </EuiButton>
                ),
              }}
              saveStateStorage={{
                system: 'localStorage',
                key: 'wz-agents-overview-table',
              }}
              tableProps={{
                tableLayout: 'auto',
                cellProps: getCellProps,
              }}
              hasAgents={true}
              setAgents={this.setAgents.bind(this)}
              hasActionButton={true}
              assignGroup={this.assignGroup.bind(this)}
              setIsBlockDomainModalVisible={this.setIsBlockDomainModalVisible.bind(this)}
              blockUSB={this.blockUSB.bind(this)}
              unBlockUSB={this.unBlockUSB.bind(this)}
            />
          </EuiFlexItem>
          {this.state.isBlockDomainModelVisible ? (
            <EuiConfirmModal
              title="Block Domains"
              onCancel={() => {
                this.setIsBlockDomainModalVisible(false);
              }}
              onConfirm={() => {
                this.onConfirmClick();
                this.setIsBlockDomainModalVisible(false);
              }}
              cancelButtonText="Cancel"
              confirmButtonText="Block"
              buttonColor="primary"
              defaultFocusedButton="confirm"
            >
              <p style={{ maxWidth: '500px' }}>
                Enter the domain names to be blocked on the selected agent machine, separating each
                domain with a comma.
              </p>
              {/* <p>Selected agent ID: <b>{selectedAgent.agentId}</b></p> */}
              <EuiTextArea
                placeholder="testdomain.com,testdomain2.com"
                onBlur={(e) => this.setState({ blockDomainTextArea: e.target.value })}
                fullWidth
                aria-label="Block Domain Input"
              />
            </EuiConfirmModal>
          ) : (
            <></>
          )}
          {this.state.isDeleteAgentModalVisible ? (
            <EuiConfirmModal
              title="Delete agent"
              onCancel={() => {
                this.setIsDeleteAgentModalVisible(false);
              }}
              onConfirm={() => {
                this.onDeleteConfirmClick();
                this.setIsDeleteAgentModalVisible(false);
              }}
              cancelButtonText="Cancel"
              confirmButtonText="Delete"
              buttonColor="danger"
              defaultFocusedButton="confirm"
            >
              <p>Selected agent will be removed from the manager.</p>
            </EuiConfirmModal>
          ) : (
            <></>
          )}
          {this.state.isRestartAgentModalVisible ? (
            <EuiConfirmModal
              title="Restart agent"
              onCancel={() => {
                this.setIsRestartAgentModalVisible(false);
              }}
              onConfirm={() => {
                this.onRestartConfirmClick();
                this.setIsRestartAgentModalVisible(false);
              }}
              cancelButtonText="Cancel"
              confirmButtonText="Restart"
              buttonColor="primary"
              defaultFocusedButton="confirm"
            >
              <p>Selected Agent will be restarted.</p>
            </EuiConfirmModal>
          ) : (
            <></>
          )}
        </EuiFlexGroup>
      );
    }
    // actionGroupButtons =
    filterGroupBadge = (group) => {
      this.setState({
        filters: {
          default: { q: 'id!=000' },
          q: `id!=000;group=${group}`,
        },
      });
    };

    renderGroups(groups) {
      return Array.isArray(groups) ? (
        <GroupTruncate
          groups={groups}
          length={25}
          label={'more'}
          action={'filter'}
          filterAction={this.filterGroupBadge}
          {...this.props}
        />
      ) : undefined;
    }

    renderIsolationStatus(status) {
      var color = 'success';
      var label = 'normal';
      if (!!status && status.includes('isolation')) {
        color = 'danger';
        label = 'isolation';
      }
      if (!!status && status.includes('q-isolation')) {
        color = 'warning';
        label = 'pending isolation';
      }
      return <EuiHealth color={color}>{label}</EuiHealth>;
    }

    render() {
      const table = this.tableRender();

      return (
        <div>
          <EuiPanel paddingSize="m">{table}</EuiPanel>
        </div>
      );
    }
  }
);

AgentsTable.propTypes = {
  wzReq: PropTypes.func,
  addingNewAgent: PropTypes.func,
  downloadCsv: PropTypes.func,
  timeService: PropTypes.func,
  reload: PropTypes.func,
};
