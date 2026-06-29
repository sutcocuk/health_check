export type Severity = 'critical' | 'warning' | 'info' | 'ok' | 'na';

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'info' | 'unknown';

export interface HealthCheck {
  id: string;
  title: string;
  category: Category;
  description: string;
  failureText: string;
  suggestedAction: string;
  search: string;
  drilldown?: string;
  docLink?: string;
  docTitle?: string;
  tags: string[];
  applicableTo?: string;
  source: 'monitoring_console' | 'health_assistant' | 'smt' | 'ps_assessment';
  status: CheckStatus;
  checkNumber?: string;
}

export type Category =
  | 'Overview'
  | 'Security'
  | 'System and Environment'
  | 'Data Collection'
  | 'Data Indexing'
  | 'Data Search'
  | 'Splunk Miscellaneous'
  | 'Upgrade Readiness';

export const CATEGORIES: Category[] = [
  'Overview',
  'Security',
  'System and Environment',
  'Data Collection',
  'Data Indexing',
  'Data Search',
  'Splunk Miscellaneous',
  'Upgrade Readiness',
];

export const checks: HealthCheck[] = [
  // ─── SYSTEM AND ENVIRONMENT ───────────────────────────────────────────────
  {
    id: 'system_hardware_provisioning_assessment',
    title: 'System Hardware Provisioning Assessment',
    category: 'System and Environment',
    checkNumber: '3.1.2',
    description:
      'Evaluates the hardware specifications of Splunk instances tasked with indexing and/or searching data, using reference hardware (minimum 12 CPU cores and 12 GB RAM).',
    failureText:
      'One or more hosts has returned CPU or memory specifications that fall below reference hardware recommendations. This might adversely affect indexing or search performance.',
    suggestedAction:
      'If you are experiencing performance issues, consider upgrading hosts to meet or exceed the recommended hardware specs.',
    search: `| rest $rest_scope$ /services/server/info
| eval cpu_core_count = if(isnotnull(numberOfVirtualCores), numberOfVirtualCores, numberOfCores)
| eval physical_memory_GB = round(physicalMemoryMB / 1024, 0)
| fields splunk_server cpu_core_count physical_memory_GB
| eval severity_level = case(cpu_core_count <= 4 OR physical_memory_GB <= 4, 2, cpu_core_count < 12 OR physical_memory_GB < 12, 1, cpu_core_count >= 12 AND physical_memory_GB >= 12, 0, true(), -1)
| rename splunk_server AS instance cpu_core_count AS "cpu_core_count (current / recommended)" physical_memory_GB AS "physical_memory_GB (current / recommended)"
| fieldformat cpu_core_count (current / recommended) = 'cpu_core_count (current / recommended)'." / 12"
| fieldformat physical_memory_GB (current / recommended) = 'physical_memory_GB (current / recommended)'." / 12"`,
    tags: ['best_practices', 'capacity', 'scalability'],
    applicableTo: 'dmc_group_search_head, dmc_group_indexer',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.hardware.reference',
    docTitle: 'recommended minimum hardware',
  },
  {
    id: 'assessment_of_server_ulimits',
    title: 'Assessment of Server ulimits',
    category: 'System and Environment',
    checkNumber: '3.1.3',
    description:
      'Checks whether the machine is provisioned with ulimit settings (file descriptors, user processes, and data segment size) that are adequate for running Splunk software.',
    failureText:
      'One or more Splunk instances are running on a host that has one or more resource limits set below official recommendations.',
    suggestedAction:
      'Persistently modify resource limits per documented best practices.',
    search: `| rest $rest_scope$ /services/server/info
| join type=outer splunk_server [rest $rest_scope$ /services/server/sysinfo | fields splunk_server ulimits.data_segment_size ulimits.open_files ulimits.user_processes]
| eval ulimits.data_segment_size = if(isnotnull('ulimits.data_segment_size'), 'ulimits.data_segment_size', "unavailable")
| eval ulimits.open_files = if(isnotnull('ulimits.open_files'), 'ulimits.open_files', "unavailable")
| eval ulimits.user_processes = if(isnotnull('ulimits.user_processes'), 'ulimits.user_processes', "unavailable")
| eval sev_segment_size = case('ulimits.data_segment_size' == -1 OR 'ulimits.data_segment_size' >= 20000000000, 0, 'ulimits.data_segment_size' == "unavailable", -1, True(), 2)
| eval sev_open_files = case('ulimits.open_files' == -1 OR 'ulimits.open_files' >= 64000, 0, 'ulimits.open_files' == "unavailable", -1, True(), 2)
| eval sev_user_processes = case('ulimits.user_processes' == -1 OR 'ulimits.user_processes' >= 16000, 0, 'ulimits.user_processes' == "unavailable", -1, True(), 2)
| eval severity_level = max(sev_segment_size, sev_open_files, sev_user_processes)
| fields splunk_server ulimits.data_segment_size ulimits.open_files ulimits.user_processes severity_level
| rename splunk_server AS instance`,
    tags: ['best_practices', 'operating_system'],
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.software.ulimit',
    docTitle: 'Splunk software ulimit requirements',
  },
  {
    id: 'linux_kernel_transparent_huge_pages',
    title: 'Linux Kernel Transparent Huge Pages',
    category: 'System and Environment',
    description:
      'Attempts to determine whether Splunk is running on a Linux server where kernel transparent huge pages are enabled. Relevant only for Linux, requires Splunk Enterprise 6.5 or higher.',
    failureText:
      'One or more Splunk instances are running on a host that has kernel transparent huge pages enabled. This can significantly reduce performance and is against best practice.',
    suggestedAction: 'Turn off kernel transparent huge pages.',
    search: `| rest $rest_scope$ /services/server/info
| join type=outer splunk_server [rest $rest_scope$ /services/server/sysinfo | fields splunk_server transparent_hugepages.*]
| eval transparent_hugepages.effective_state = if(isnotnull('transparent_hugepages.effective_state'), 'transparent_hugepages.effective_state', "unknown")
| eval severity_level = case('transparent_hugepages.effective_state' == "unavailable", -1, 'transparent_hugepages.effective_state' == "ok", 0, 'transparent_hugepages.effective_state' == "unknown", 1, 'transparent_hugepages.effective_state' == "bad", 2)
| fields splunk_server transparent_hugepages.enabled transparent_hugepages.defrag transparent_hugepages.effective_state severity_level
| rename splunk_server AS instance`,
    tags: ['best_practices', 'operating_system'],
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.hardware.thp',
    docTitle: 'transparent huge pages',
  },
  {
    id: 'near_critical_disk_usage',
    title: 'Near-Critical Disk Usage',
    category: 'System and Environment',
    description:
      'Checks the disk usage of partitions that Splunk Enterprise reads or writes to. Raises warning when usage is above 90%.',
    failureText:
      'At least one partition, on at least one instance, was found with disk usage above 90%.',
    suggestedAction:
      'Check the data retention policies on the affected instances to ensure that the disk doesn\'t fill up. Alternatively, provision more disk space.',
    search: `| rest $rest_scope$ /services/server/status/partitions-space
| eval free = if(isnotnull(available), available, free)
| eval usage = capacity - free
| eval pct_usage = floor(usage / capacity * 100)
| stats first(pct_usage) AS pct_usage by splunk_server, mount_point
| eval severity_level = case(pct_usage < 90, 0, pct_usage >= 90, 2, True(), -1)
| eval mount_info = if(isNull(pct_usage), "No disk information available", mount_point.": ".pct_usage."%")
| stats values(mount_info) AS mount_information max(severity_level) AS severity_level by splunk_server
| rename splunk_server AS instance`,
    drilldown: '/app/splunk_monitoring_console/resource_usage_machine?form.machine=$machine$',
    tags: ['capacity', 'storage', 'disk_space'],
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.disk.usage.indexer',
    docTitle: 'disk usage on indexers',
  },

  // ─── DATA COLLECTION ─────────────────────────────────────────────────────
  {
    id: 'file_descriptor_limits',
    title: 'File Descriptor Limits',
    category: 'Data Collection',
    checkNumber: '3.2.1',
    description:
      'Checks for file descriptor cache full events in the last 24 hours. No results means no file descriptor limit problems detected.',
    failureText:
      'One or more hosts is running into file descriptor cache limits, which can impact data collection.',
    suggestedAction:
      'Increase the file descriptor limit (ulimit -n) on affected hosts per Splunk best practices.',
    search: `index=_internal "File descriptor cache is full"
| rex "is full \\((?<fd_limit>\\d+)"
| stats count as Count sparkline as Trend by host, fd_limit
| sort -fd_limit, -Count`,
    tags: ['data_collection', 'operating_system'],
    source: 'smt',
    status: 'unknown',
  },
  {
    id: 'throughput_limit',
    title: 'Throughput Limit',
    category: 'Data Collection',
    checkNumber: '3.2.2',
    description:
      'Checks for throughput limit warnings in the last 24 hours. No results means no throughput limit problems detected.',
    failureText:
      'One or more hosts is hitting throughput rate limits, which may indicate a license constraint.',
    suggestedAction:
      'Review license usage. Consider upgrading the license if throughput limits are consistently hit.',
    search: `index=_internal sourcetype=splunkd "current data throughput"
| rex "Current data throughput \\((?<kb>\\S+)"
| eval rate=case(kb < 500, "256", kb > 499 AND kb < 520, "512", kb > 520 AND kb < 770,"768", kb>771 AND kb<1210, "1024", 1=1, ">1024")
| stats count as Count sparkline as Trend by host, rate
| where Count > 4
| rename rate as "Throughput rate(kb)"
| sort -"Throughput rate(kb)",-Count`,
    tags: ['data_collection', 'licensing'],
    source: 'smt',
    status: 'unknown',
  },
  {
    id: 'data_inputs',
    title: 'Data Inputs Overview',
    category: 'Data Collection',
    checkNumber: '3.2.3',
    description:
      'Lists all active (non-disabled) data inputs across all Splunk instances with their app, type, index, and sourcetype.',
    failureText: 'Review active data inputs for unexpected or misconfigured entries.',
    suggestedAction:
      'Verify that all data inputs are correctly configured and pointing to the right indexes and sourcetypes.',
    search: `| rest splunk_server=* /servicesNS/-/-/data/inputs/all
| search disabled=0
| table splunk_server eai:acl.app eai:type title index sourcetype`,
    tags: ['data_collection', 'inputs'],
    source: 'smt',
    status: 'unknown',
  },
  {
    id: 'files_ignored_in_monitor_path',
    title: 'Files Ignored in Monitor Path',
    category: 'Data Collection',
    checkNumber: '3.2.4',
    description:
      'Detects files being ignored in monitored paths in the last 24 hours. No results means no ignored file problems detected.',
    failureText:
      'One or more files are being ignored in monitored paths, possibly due to file too large, binary content, or too many files.',
    suggestedAction:
      'Review the reasons for ignored files and adjust monitor stanza settings as needed (TRUNCATE, MAX_EVENTS, blacklist, etc.).',
    search: `index=_internal "ignoring file"
| rex "Ignoring file '(?<file_path>\\S[^']+)' due to: (?<reason>.+)"
| stats values(reason) AS Reasons sparkline as Trend dc(file_path) AS Unique_Paths count as Count by host
| sort -Unique_Paths,-count`,
    tags: ['data_collection', 'monitor'],
    source: 'smt',
    status: 'unknown',
  },
  {
    id: 'event_processing_issues',
    title: 'Event-Processing Issues',
    category: 'Data Collection',
    description:
      'Checks for warnings emitted when the index-time settings in place do not allow for the proper processing of recently ingested data (in the last hour). Covers line breaking, aggregation, and timestamp issues.',
    failureText: `Some recently ingested events are triggering event-processing warnings indicating:
1. Lines in the event are too long, exceeding props.conf / TRUNCATE
2. There are too many lines per event, exceeding props.conf / MAX_EVENTS
3. The extraction of event time stamps was partially or completely unsuccessful`,
    suggestedAction:
      'Check the events that are triggering these warnings. Adjust event-processing settings as needed to ensure their proper ingestion.',
    search: `\`dmc_set_index_internal\` $rest_scope$ search_group=dmc_group_indexer earliest=-60m
  (source=*splunkd.log* (component=AggregatorMiningProcessor OR component=LineBreakingProcessor OR component=DateParserVerbose) (log_level=WARN OR log_level=ERROR))
  OR (source=*metrics.log* group=thruput name=index_thruput)
| stats sum(eval(round(ev,0))) AS event_count count(eval(component=="AggregatorMiningProcessor")) AS aggregation_issues count(eval(component=="LineBreakingProcessor")) AS line_breaking_issues count(eval(component=="DateParserVerbose")) AS date_parsing_issues by host
| eval crap_score = round((aggregation_issues + line_breaking_issues + date_parsing_issues) / event_count * 1000, 3)
| eval severity_level = case(crap_score == 0, 0, crap_score > 0 AND crap_score < 1, 1, True(), 2)
| rename host AS instance
| fields - crap_score`,
    tags: ['event_breaking', 'indexing', 'timestamp_extraction'],
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.eventprocess.linebreak',
    docTitle: 'event processing issues',
  },

  // ─── DATA INDEXING ────────────────────────────────────────────────────────
  {
    id: 'expiring_or_expired_licenses',
    title: 'Expiring or Expired Licenses',
    category: 'Data Indexing',
    checkNumber: '3.3.2',
    description:
      'Checks for licenses that are about to expire (within 14 days) or have already expired.',
    failureText:
      'One or more licenses installed on your license manager(s) have expired or will expire soon.',
    suggestedAction:
      'Contact your sales representative if you need a new license. Make sure to delete already expired licenses on the license manager page.',
    search: `| rest $rest_scope$ splunk_server_group=dmc_group_license_master /services/licenser/licenses
| join type=outer group_id splunk_server [
    rest $rest_scope$ splunk_server_group=dmc_group_license_master /services/licenser/groups
    | where is_active = 1
    | rename title AS group_id
    | fields is_active group_id splunk_server]
| where is_active = 1
| eval days_left = floor((expiration_time - now()) / 86400)
| where NOT (quota = 1048576 OR label == "Splunk Enterprise Reset Warnings" OR label == "Splunk Lite Reset Warnings")
| eval status = case(days_left >= 14, days_left." days left", days_left < 14 AND days_left >= 0, "Expires soon: ".days_left." days left", days_left < 0, "Expired")
| eval size_gb = round(quota/1024/1024/1024,3)
| eval license_info = label." (size = ".size_gb." GB ; hash = ".license_hash.") - ".status
| eval severity_level = case(days_left >= 14, 0, days_left < 14 AND days_left >= 0, 2, days_left < 0, 3)
| stats values(license_info) AS license_information max(severity_level) AS severity_level by splunk_server
| rename splunk_server AS instance`,
    tags: ['licensing'],
    applicableTo: 'dmc_group_license_master',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.expired.license',
    docTitle: 'expired licenses',
  },
  {
    id: 'license_warnings_and_violations',
    title: 'License Warnings and Violations',
    category: 'Data Indexing',
    description:
      'Checks whether any license peers have incurred license warnings in the current licensing window and whether any are in violation (≥45 warnings = violation).',
    failureText:
      'One or more license peers have warnings or are in violation. An indexer in violation is not capable of serving searches.',
    suggestedAction:
      'Check the Monitoring Console license usage dashboards to understand how warnings were accrued. To clear violations, request a reset license from Splunk Support.',
    search: `| rest $rest_scope$ splunk_server_group=dmc_group_license_master /services/licenser/slaves
| join type=outer splunk_server [rest $rest_scope$ /services/server/info | fields version, splunk_server]
| fields label splunk_server version warning_count
| eval in_violation = if(warning_count >= 45, 1, 0)
| eval severity_level = case(in_violation == 1, 3, warning_count > 0 AND warning_count < 45, 2, warning_count == 0, 0)
| rename label AS instance splunk_server AS license_master`,
    drilldown: '/app/splunk_monitoring_console/license_usage_today?form.splunk_server=$instance$',
    tags: ['indexing', 'licensing'],
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.license.warnings.violation',
    docTitle: 'license warnings and violations',
  },
  {
    id: 'indexing_status',
    title: 'Indexing Status',
    category: 'Data Indexing',
    checkNumber: '3.3.3',
    description:
      'Tests the current status of the indexer processor on indexer instances.',
    failureText:
      'One or more of your indexers reports an abnormal state. Those indexers might be blocked or causing delays in data acquisition.',
    suggestedAction:
      'Investigate affected indexers with the Monitoring Console Indexing Performance: Instance view. You might need to restart the affected indexers.',
    search: `| rest $rest_scope$ splunk_server_group=dmc_group_indexer /services/server/introspection/indexer
| fields splunk_server, status, reason
| eval severity_level = if(status == "normal", 0, 2)
| rename splunk_server as instance`,
    drilldown: '/app/splunk_monitoring_console/indexing_performance_instance?form.splunk_server=$instance$',
    tags: ['indexing', 'buckets'],
    applicableTo: 'dmc_group_indexer',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.indexing.status',
    docTitle: 'Splunk indexing status',
  },
  {
    id: 'saturation_of_event_processing_queues',
    title: 'Saturation of Event-Processing Queues',
    category: 'Data Indexing',
    description:
      'Checks if queues on your indexers have been saturated (≥90% full) consistently in the past 15 minutes.',
    failureText:
      'One or more of the indexer queues on this instance is reporting an averaged fill percentage of 90 or more over the last 15 minutes.',
    suggestedAction:
      'Check the Monitoring Console indexing performance view for the affected indexers.',
    search: `| rest $rest_scope$ /services/server/introspection/queues
| search title=parsingQueue* OR title=aggQueue* OR title=typingQueue* OR title=indexQueue*
| eval fill_perc = round(current_size_bytes / max_size_bytes * 100,2)
| rex field=title "(?<queue_name>^\\w+)(?:\\.(?<pipeline_number>\\d+))?"
| fields splunk_server fill_perc queue_name pipeline_number
| eval severity_level = if( fill_perc > 90, 2, 0)
| chart values(fill_perc) AS fill_perc max(severity_level) AS severity_level over splunk_server by queue_name
| rename splunk_server AS instance`,
    drilldown: '/app/splunk_monitoring_console/indexing_performance_instance?form.splunk_server=$instance$',
    tags: ['indexing', 'queues'],
    applicableTo: 'dmc_group_indexer',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.indexer.highqueuefillpct',
    docTitle: 'saturation of event processing queues',
  },
  {
    id: 'missing_forwarders',
    title: 'Missing Forwarders',
    category: 'Data Indexing',
    description:
      'Checks whether any forwarders have not connected to indexers for >15 minutes. Requires the Monitoring Console forwarder monitoring feature to be enabled.',
    failureText:
      'One or more forwarders that previously communicated with your indexers have not been seen for more than 15 minutes.',
    suggestedAction:
      'Check the Forwarders: Deployment dashboard to get a full list of the impacted forwarders.',
    search: `| inputlookup dmc_forwarder_assets
| stats count AS forwarder_count by status
| eval severity_level = case(status=="active", 0, status=="missing", 2, true(), -1)
| eventstats max(severity_level) AS max_severity_level
| where severity_level = max_severity_level
| fields status forwarder_count severity_level`,
    drilldown: '/app/splunk_monitoring_console/forwarder_deployment',
    tags: ['forwarding', 'batchreader', 'tailreader'],
    applicableTo: 'dmc_group_indexer',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.forwarders.setup',
    docTitle: 'forwarder setup',
  },
  {
    id: 'local_indexing_on_non_indexer_instances',
    title: 'Local Indexing on Non-Indexer Instances',
    category: 'Data Indexing',
    description:
      'Checks whether any non-indexer instances (search heads, cluster managers, license managers, deployment servers, deployers) are indexing their own events locally instead of forwarding to indexers.',
    failureText:
      'One or more non-indexer instances is not forwarding their events to the indexers. This can isolate some of your data and prevent some Monitoring Console dashboards from working.',
    suggestedAction:
      'Make sure that all non-indexer instances are forwarding their internal events to the indexers, per best practices.',
    search: `| rest $rest_scope$ /services/server/info
| fields splunk_server isForwarding server_roles
| where (server_roles=="search_head" OR server_roles=="cluster_master" OR server_roles=="license_master" OR server_roles=="shc_deployer" OR server_roles=="deployment_server" OR isNull(server_roles))
| eval severity_level = case( isForwarding==1, 0, isForwarding == 0, 2, true(), -1)
| rename splunk_server AS instance`,
    tags: ['best_practices', 'forwarding', 'indexing'],
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.internallogs.sh',
    docTitle: 'indexing on search heads',
  },

  // ─── DATA SEARCH ─────────────────────────────────────────────────────────
  {
    id: 'search_scheduler_skip_ratio',
    title: 'Search Scheduler Skip Ratio',
    category: 'Data Search',
    checkNumber: '3.4.1',
    description:
      'Checks whether scheduled searches were skipped in the past hour on search heads.',
    failureText:
      'Scheduled searches are being skipped on one or more search heads.',
    suggestedAction:
      'Check the Monitoring Console Scheduler Activity: Instance dashboard for each affected search head to determine the problem.',
    search: `earliest=-60m \`dmc_set_index_internal\` search_group=dmc_group_search_head sourcetype=scheduler (status="completed" OR status="skipped")
| stats count(eval(status=="completed" OR status=="skipped")) AS total_executions, count(eval(status=="skipped")) AS skipped_executions by host
| eval skip_ratio = skipped_executions/total_executions * 100
| eval severity_level = case(skip_ratio == 0, 0, skip_ratio > 0, 2)
| eval skip_ratio = round(skip_ratio, 2)."%"
| rename host AS instance
| fields instance total_executions skipped_executions skip_ratio severity_level`,
    drilldown: '/app/splunk_monitoring_console/scheduler_activity_instance?form.splunk_server=$instance$',
    tags: ['scheduler', 'searches_skipped'],
    applicableTo: 'dmc_group_search_head',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.scheduler.skip',
    docTitle: 'skipping scheduled searches',
  },
  {
    id: 'skipped_saved_searches',
    title: 'Skipped Saved Searches (non-Accelerate)',
    category: 'Data Search',
    checkNumber: '3.4.1.1',
    description:
      'Lists skipped scheduled searches (excluding acceleration searches) with reasons and concurrency limits.',
    failureText:
      'One or more saved searches are being skipped. This indicates concurrency or resource constraints.',
    suggestedAction:
      'Review skipped searches and consider adjusting schedule intervals, priority, or search head capacity.',
    search: `index=_internal sourcetype=scheduler (log_level=INFO) status=skipped NOT savedsearch_name=_ACCELERATE*
| rename host as instance
| stats count as "Skipped Searches" by app instance reason concurrency_limit user`,
    tags: ['scheduler', 'searches_skipped'],
    source: 'smt',
    status: 'unknown',
  },
  {
    id: 'distributed_search_health_assessment',
    title: 'Distributed Search Health Assessment',
    category: 'Data Search',
    description:
      'Checks the status of the search peers (indexers) of each search head and assesses the overall health of distributed search on a per search head basis.',
    failureText:
      'One or more search heads are reporting unhealthy search peers.',
    suggestedAction:
      'Check the Monitoring Console Distributed Search: Instance view for more information. Review resource usage and general instance health of the unhealthy peers.',
    search: `| rest $rest_scope$ splunk_server_group=dmc_group_search_head /services/search/distributed/peers
| fields splunk_server peerName server_roles status status_details
| eval peer_health = case(status == "Up" AND isnull(status_details), "optimal", status != "Down" AND isnotnull(status_details), "degraded", status == "Down", "down", status!= "Up" OR status != "Down", "inconclusive")
| stats count AS peer_count count(eval(peer_health == "optimal")) AS peer_count_optimal count(eval(peer_health == "degraded")) AS peer_count_degraded count(eval(peer_health == "down")) AS peer_count_down count(eval(peer_health == "inconclusive")) AS peer_count_inconclusive by splunk_server
| eval severity_level = case(peer_count_down > 0, 3, peer_count_degraded > 0, 2, peer_count_inconclusive > 0, 1, peer_count_optimal > 0, 0, True(), -1)
| rename splunk_server AS search_head`,
    tags: ['distributed_search', 'indexers'],
    applicableTo: 'dmc_group_search_head',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.distributedsearch',
    docTitle: 'Splunk distributed search',
  },

  // ─── SPLUNK MISCELLANEOUS ────────────────────────────────────────────────
  {
    id: 'users_and_roles',
    title: 'Users and Role Assignments',
    category: 'Splunk Miscellaneous',
    checkNumber: '3.5.1',
    description:
      'Lists all Splunk users with their roles across all instances.',
    failureText:
      'Review users and role assignments for unauthorized or incorrect role configurations.',
    suggestedAction:
      'Ensure each user has the minimum necessary permissions. Remove unused accounts.',
    search: `| rest /services/authentication/users splunk_server=*
| fields title roles realname splunk_server
| rename title as userName
| rename realname as Name`,
    tags: ['security', 'users', 'roles'],
    source: 'smt',
    status: 'unknown',
  },
  {
    id: 'splunkd_errors_warnings',
    title: 'Splunkd Log Errors, Warnings and Critical',
    category: 'Splunk Miscellaneous',
    checkNumber: '3.5.2',
    description:
      'Checks the splunkd.log for ERROR, WARN, FATAL, and CRITICAL log levels.',
    failureText:
      'ERROR, WARNING, or CRITICAL messages found in splunkd.log indicating potential system issues.',
    suggestedAction:
      'Review the error messages and address any recurring issues. Pay attention to FATAL and CRITICAL messages.',
    search: `earliest=-24h index=_internal source="*splunkd.log" (log_level=ERROR OR log_level=WARN* OR log_level=FATAL OR log_level=CRITICAL)
| stats count by log_level
| eval severity_level = if(count > 0, 2, 0)`,
    tags: ['logs', 'errors'],
    source: 'smt',
    status: 'unknown',
  },
  {
    id: 'kv_store_status',
    title: 'KV Store Status',
    category: 'Splunk Miscellaneous',
    description:
      'Checks whether the KV Store is running as expected.',
    failureText:
      'The status of the KV Store feature on one or more instances is abnormal.',
    suggestedAction:
      'Check mongod.log to find out why the KV Store process may have failed to start.',
    search: `| rest $rest_scope$ splunk_server_group=dmc_group_kv_store /services/server/info
| fields splunk_server kvStoreStatus
| eval severity_level = case(isNull(kvStoreStatus), -1, kvStoreStatus == "ready", 0, kvStoreStatus == "disabled" OR kvStoreStatus == "starting", 1, kvStoreStatus == "failed", 2)
| rename splunk_server AS instance`,
    drilldown: '/app/splunk_monitoring_console/kv_store_instance?form.splunk_server=$instance$',
    tags: ['kv_store'],
    applicableTo: 'dmc_group_kv_store',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.kvstore.status',
    docTitle: 'KV store statuses',
  },
  {
    id: 'excessive_physical_memory_usage',
    title: 'Excessive Physical Memory Usage',
    category: 'Splunk Miscellaneous',
    description:
      'Assesses system-wide physical memory usage and raises a warning for servers where it is >90%.',
    failureText:
      'One or more machines are using more than 90% of installed physical memory and may be at risk of an outage.',
    suggestedAction:
      'Check individual machines to identify the source of the excessive memory usage with the Monitoring Console Resource Usage pages.',
    search: `| rest $rest_scope$ /services/server/status/resource-usage/hostwide
| eval percentage = round(mem_used/mem,3)*100
| eval severity_level = if(percentage >= 90, 2, 0)
| fields splunk_server, mem_used, mem, percentage, severity_level
| rename splunk_server AS instance, mem AS "Physical memory installed (MB)", percentage AS "Memory used (%)", mem_used AS "Memory used (MB)"`,
    drilldown: '/app/splunk_monitoring_console/resource_usage_machine?form.machine=$machine$',
    tags: ['resource_usage'],
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.hardware.highmem',
    docTitle: 'high memory usage',
  },
  {
    id: 'orphaned_scheduled_searches',
    title: 'Orphaned Scheduled Searches',
    category: 'Splunk Miscellaneous',
    description:
      'Looks for scheduled searches that have become orphaned after their owner was deactivated (typically when a user is removed from LDAP/AD).',
    failureText:
      'One or more scheduled searches are orphaned, meaning they are no longer associated with valid owners. The scheduler will not run orphaned searches.',
    suggestedAction:
      'Identify the impacted searches. Disable, delete, or reassign ownership of the affected searches, as appropriate.',
    search: `| rest $rest_scope$ /servicesNS/-/-/saved/searches add_orphan_field=yes count=0
| where disabled=0 AND is_scheduled=1
| stats count(eval(orphan=1)) AS orphaned_search_count by splunk_server
| eval severity_level = if(orphaned_search_count > 0, 3, 0)
| rename splunk_server AS instance`,
    tags: ['configuration', 'search', 'searches_skipped'],
    applicableTo: 'dmc_group_search_head',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'learnmore.orphaned_searches',
    docTitle: 'orphaned searches',
  },
  {
    id: 'integrity_check_installed_files',
    title: 'Integrity Check of Installed Files',
    category: 'Splunk Miscellaneous',
    description:
      'Verifies the integrity of files that were installed by Splunk to detect unexpected modifications.',
    failureText:
      'One or more files that were originally installed by Splunk have been unexpectedly modified or are missing.',
    suggestedAction:
      'Review the list of files that failed the integrity check. Make sure that no default configuration files have been modified. Consider restoring non-configuration files from backup or from the Splunk package.',
    search: `| rest $rest_scope$ /services/server/info
| join type=outer splunk_server [rest $rest_scope$ /services/server/status/installed-file-integrity
    | fields splunk_server check_ready check_failures.*
    | untable splunk_server file_path check_result
    | replace "check_failures.*" WITH "*" IN file_path
    | eval check_ready = if(file_path == "check_ready", check_result, NULL)
    | eval file_path = if(file_path == "check_ready", NULL, file_path)
    | stats count(eval(isnotnull(file_path))) AS file_integrity_failures max(check_ready) AS check_ready by splunk_server]
| eval severity_level = case(check_ready != "true", -1, file_integrity_failures = 0, 0, isnull(file_integrity_failures), 1, file_integrity_failures > 0, 2, True(), -1)
| rename splunk_server AS instance`,
    drilldown: '/app/search/integrity_check_of_installed_files?form.splunk_server=$instance$',
    tags: ['configuration', 'installation'],
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.validate.files',
    docTitle: 'validating installed files',
  },
  {
    id: 'shp_to_shc_upgrade_opportunity',
    title: 'Upgrade Opportunity: Search Head Pooling → Clustering',
    category: 'Splunk Miscellaneous',
    description:
      'If you are using search head pooling and running Splunk Enterprise 6.2 or higher, migration to search head clustering is strongly recommended.',
    failureText:
      'This instance is part of a search head pool and is running Splunk Enterprise 6.2 or higher.',
    suggestedAction:
      'Consult the procedure to migrate from search head pooling to search head clustering.',
    search: `| rest $rest_scope$ /services/properties/server/pooling/state
| where value=enabled
| eval shpooling = 1
| join type=outer splunk_server [rest $rest_scope$ /services/server/info | fields version, splunk_server]
| stats max(shpooling) AS shpooling_state max(version) AS version by splunk_server
| eval severity_level = if(shpooling_state = 1 AND match(version,"^(6\\.[234]|[7-9]\\.)"), 1, 0)
| rename splunk_server AS instance`,
    tags: ['best_practices', 'configuration'],
    applicableTo: 'dmc_group_search_head',
    source: 'monitoring_console',
    status: 'unknown',
    docLink: 'healthcheck.shp.upgradenag',
    docTitle: 'upgrading from search head pooling',
  },

  // ─── SECURITY ────────────────────────────────────────────────────────────
  {
    id: 'ssl_alert_check',
    title: 'TLS Errors',
    category: 'Security',
    description:
      'Evaluates for the presence of any TLS or SSL alerts in the last hour that prevented TLS handshake completion.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a TLS handshake.',
    suggestedAction:
      'Confirm that secure communication with TLS is on for both the client and the server. Verify that the TLS settings on the client and server have common attributes such as TLS protocol versions, cipher suites, and other configurable TLS values.',
    search: `index=_internal source=*splunkd.log* "Received fatal SSL3 alert" earliest=-60m
| rex "ssl_state='(?<ssl_state>[^']+)'.*alert_description='(?<alert>[^']+)'"
| stats values(alert) AS alerts, count AS sixty_min_event_count BY host
| eval alerts = mvjoin(alerts, ", ")
| eval severity_level = 3
| rename host as instance
| append [| makeresults count=1 splunk_server=* annotate=true | rename splunk_server as instance | fillnull value="" alerts | fillnull value="0" severity_level sixty_min_event_count]
| stats values(alerts) as alerts sum(sixty_min_event_count) as sixty_min_event_count sum(severity_level) as severity_level by instance`,
    tags: ['ssl', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'cipher_suite_mismatch_check',
    title: 'TLS Cipher Suite Mismatches',
    category: 'Security',
    description:
      'Evaluates for cipher suite mismatches between server and client in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a TLS handshake because its configuration and the connecting client did not contain any mutually shared ciphers.',
    suggestedAction:
      "Inspect the 'sslVersions' and 'cipherSuite' setting values in the server configuration stanza. Determine the highest mutually-shared TLS protocol version and ensure at least one mutually-shared cipher exists.",
    search: `index=_internal source=*splunkd.log* "ssl3_get_client_hello:no shared cipher" earliest=-60m
| stats count AS sixty_min_event_count BY host
| eval severity_level = 3
| rename host as instance
| append [| makeresults count=1 splunk_server=* annotate=true | rename splunk_server as instance | fillnull value="0" severity_level sixty_min_event_count]
| stats sum(sixty_min_event_count) as sixty_min_event_count sum(severity_level) as severity_level by instance`,
    tags: ['ssl', 'configuration', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'deprecated_tls_version_check',
    title: 'Deprecated TLS Protocol Versions in Splunk Configuration',
    category: 'Security',
    description:
      'Evaluates whether any TLS protocol version other than TLS 1.2 or TLS 1.3 is present in the Splunk configuration.',
    failureText:
      "The configuration on this Splunk platform instance contains a deprecated TLS protocol version lower than 1.2 in either the 'sslVersions' or 'sslVersionsforClient' settings.",
    suggestedAction:
      "In any configuration (.conf) file, replace values for 'sslVersions' and 'sslVersionsforClient' settings that are not \"tls1.2\", \"tls1.3\", or \"tls1.2,tls1.3\".",
    search: `| rest splunk_server=* "/services/configs/conf-server" | eval conf = "server"
| append [ | rest splunk_server=* "/servicesNS/-/-/configs/conf-inputs" | eval conf = "inputs" ]
| append [ | rest splunk_server=* "/servicesNS/-/-/configs/conf-outputs" | eval conf = "outputs" ]
| append [ | rest splunk_server=* "/servicesNS/-/-/configs/conf-web" | eval conf = "web" ]
| stats values(sslVersions) AS sslVersions values(sslVersionsForClient) AS sslVersionsForClient by splunk_server conf title eai:appName
| search sslVersions=* OR sslVersionsForClient=*
| where (isnotnull(sslVersions) AND NOT (sslVersions="tls1.2" OR sslVersions="tls1.3"))
  OR (isnotnull(sslVersionsForClient) AND NOT (sslVersionsForClient="tls1.2" OR sslVersionsForClient="tls1.3"))
| eval severity_level = 3
| rename splunk_server as instance`,
    tags: ['ssl', 'configuration', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'incorrect_tls_protocol_version_check',
    title: 'Incorrect TLS Protocol Versions',
    category: 'Security',
    description:
      'Evaluates for TLS handshake failures where server and client do not share a common TLS version in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a TLS handshake because it and a peer did not share a common TLS version.',
    suggestedAction:
      "Verify that the client initiates TLS connections using TLS version 1.2. On the Splunk platform instance, verify that the 'sslVersions' has a value of \"tls1.2\".",
    search: `index=_internal source=*splunkd.log* ("Received fatal SSL3 alert" AND "alert_description='protocol version'") OR "SSL23_GET_CLIENT_HELLO:unknown protocol" earliest=-60m
| stats count AS sixty_min_event_count BY host
| eval severity_level = 3
| rename host as instance`,
    tags: ['ssl', 'configuration', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'invalid_certificate_check',
    title: 'Invalid TLS Certificates',
    category: 'Security',
    description:
      'Evaluates for TLS/SSL alerts indicating an invalid certificate (unknown, expired, bad) in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a TLS handshake because a server or client certificate was not valid.',
    suggestedAction:
      "Confirm that the peer certificate is readable and valid. Use the 'splunk cmd openssl' CLI command. Confirm the certificate is not expired and verify that system clocks are in sync.",
    search: `index=_internal source=*splunkd.log* "Received fatal SSL3 alert" earliest=-60m
| rex "ssl_state='(?<ssl_state>[^']+)'.*alert_description='(?<alert>[^']+)'"
| where alert in ("certificate unknown", "certificate expired", "bad certificate")
| stats values(alert) AS alerts, count AS sixty_min_event_count BY host
| eval severity_level = 3
| rename host as instance`,
    tags: ['ssl', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'common_name_mismatch_check',
    title: 'Certificate Common Name Mismatches',
    category: 'Security',
    description:
      'Evaluates for certificate common name mismatch events during certificate name validation in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a TLS handshake because it received a certificate with a common name (CN) that did not match the value it expected.',
    suggestedAction:
      "Review the value for the 'sslCommonNameToCheck' setting in the configuration stanza. Verify the CN of the certificate. These values must match.",
    search: `index=_internal source=*splunkd.log* "X509 certificate" "did not match any allowed names" earliest=-60m
| rex "CN=(?<common_name>[^)]+).*allowed names \\((?<allowed_names>[^)]+)\\)"
| eval observed_cn_vs_allowed = "{CN: " . common_name . "; Allowed CNs: " . allowed_names . "}"
| stats values(observed_cn_vs_allowed) AS observed_cns_vs_allowed BY host
| eval severity_level = 3
| rename host as instance`,
    tags: ['ssl', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'unknown_ca_check',
    title: 'Unknown Certificate Authority Certificates',
    category: 'Security',
    description:
      'Evaluates for TLS alerts indicating an unknown CA certificate in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a TLS handshake because it could not find valid CA certificate(s) in the trust store.',
    suggestedAction:
      "Confirm that the Splunk platform instance has the 'sslRootCAPath' setting configured. If no valid CA certificate exists in the trust store, add one.",
    search: `index=_internal source=*splunkd.log* "Received fatal SSL3 alert" "alert_description='unknown CA'" earliest=-60m
| stats count AS sixty_min_event_count BY host
| eval severity_level = 3
| rename host as instance`,
    tags: ['ssl', 'configuration', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'missing_cipher_check',
    title: 'Missing TLS Ciphers',
    category: 'Security',
    description:
      'Checks for TLS handshake failures due to no compatible ciphers in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a TLS handshake because its configuration did not contain any ciphers compatible with the TLS version used.',
    suggestedAction:
      "Inspect the 'sslVersions', 'sslVersionsforClient', and 'cipherSuite' setting values. Confirm there is at least one cipher compatible with the TLS version in use.",
    search: `index=_internal source=*splunkd.log* "SSL23_CLIENT_HELLO:no ciphers available" earliest=-60m
| stats count AS sixty_min_event_count BY host
| eval severity_level = 3
| rename host as instance`,
    tags: ['ssl', 'configuration', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'missing_x509_ca_basic_constraint_check',
    title: 'Missing CA:TRUE basicConstraint X.509 v3 Extensions',
    category: 'Security',
    description:
      'Evaluates for CA certificate files missing the "CA:TRUE" basicConstraint X.509 v3 extension in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance did not load a CA certificate file because the certificate did not contain the "CA:TRUE" basicConstraint X.509 v3 extension.',
    suggestedAction:
      'Inspect the certificate in the Splunk platform instance CA trust store. Confirm it contains an X.509 v3 basicConstraint field with a value of "CA:TRUE".',
    search: `index=_internal source=*splunkd.log* "not a valid Certificate Authority (CA)" "required=X509_CA_V3_basicConstraints" earliest=-60m
| stats count AS sixty_min_event_count BY host
| eval severity_level = 3
| rename host as instance`,
    tags: ['ssl', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'mtls_certificate_verification_failure_check',
    title: 'Mutual TLS (mTLS) Certificate Verification Failures',
    category: 'Security',
    description:
      'Evaluates for failed client certificate verification for mutual TLS (mTLS) in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a mutual TLS handshake because it failed to verify the certificate that a connecting client presented.',
    suggestedAction:
      "Confirm that the client certificate is readable and valid. Use the 'splunk cmd openssl' CLI command. Verify clocks are in sync and the CN matches 'sslCommonNameToCheck'.",
    search: `index=_internal source=*splunkd.log* "ssl3_get_client_certificate:certificate verify failed" earliest=-60m
| stats count AS sixty_min_event_count BY host
| eval severity_level = 3
| rename host as instance`,
    tags: ['ssl', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'mtls_missing_client_certificate_check',
    title: 'Mutual TLS (mTLS) Missing Client Certificates',
    category: 'Security',
    description:
      'Evaluates for mTLS failures where a client failed to produce a certificate in the last hour.',
    failureText:
      'Within the last 60 minutes, this Splunk platform instance could not complete a mutual TLS handshake because it did not receive a certificate from the connecting client.',
    suggestedAction:
      "Confirm that the client is configured to present a client certificate. Use the 'splunk cmd openssl' CLI command if the client is a Splunk platform node.",
    search: `index=_internal source=*splunkd.log* "peer did not return a certificate" earliest=-60m
| stats count AS sixty_min_event_count BY host
| eval severity_level = 3
| rename host as instance`,
    tags: ['ssl', 'configuration', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'deprecated_call_check',
    title: 'Deprecated REST API Call Check',
    category: 'Security',
    description:
      'Evaluates whether calls are made to deprecated REST API version 1.0 endpoints and marks as Critical if any are present in the last 7 days.',
    failureText:
      'Within the last 7 days one or more calls to deprecated search endpoints were made.',
    suggestedAction:
      'Review any apps or users that are calling these deprecated endpoints and update them to use the latest REST endpoints.',
    search: `earliest=-7d@d index=_internal method=GET (sourcetype::splunkd_access OR sourcetype::splunkd_ui_access OR sourcetype::splunk_web_access)
    (uri="*/results_preview?search=*" OR uri="*/results?search=*" OR uri="*/results/export?search=*"
    OR uri="*/events?search=*" OR uri="*/events/export?search=*" OR uri="*/jobs/export*" OR uri="*/parser*")
    AND NOT uri="*/v2/*"
| eval metric="user=".user." uri=".uri
| rename host AS instance
| stats count AS deprecated_api_calls by instance
| eval severity_level=if(deprecated_api_calls>0,3,0)`,
    docLink: 'https://docs.splunk.com/Documentation/SplunkCloud/9.2.2406/RESTREF/RESTsearch#Semantic_API_versioning',
    docTitle: 'REST API Reference Manual',
    tags: ['search', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'v1_search_api_disabled',
    title: 'v1 Search API Block Check',
    category: 'Security',
    description:
      'Evaluates the Splunk configuration for the setting that blocks access to version 1 of the Search API.',
    failureText:
      'The configuration on this Splunk platform instance did not contain the expected value of "true" for the setting v1APIBlockGETSearchLaunch in the [global] stanza of the restmap.conf file.',
    suggestedAction:
      'Configure v1APIBlockGETSearchLaunch = true in the [global] stanza of the restmap.conf configuration file before upgrading to Splunk Enterprise version 10.0.',
    search: `| rest services/configs/conf-restmap
| fields splunk_server, v1APIBlockGETSearchLaunch
| stats values(v1APIBlockGETSearchLaunch) AS v1APIBlockGETSearchLaunch BY splunk_server
| fillnull v1APIBlockGETSearchLaunch value=0
| rename splunk_server AS instance, v1APIBlockGETSearchLaunch AS metric
| eval severity_level = case(metric=1, 0, true(), 2)`,
    docLink: 'https://docs.splunk.com/Documentation/Splunk/10.0.0/RESTREF/RESTsearch',
    docTitle: 'REST API Reference Manual',
    tags: ['search', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'end_of_life_splunk_built_apps',
    title: 'Splunk-Built Apps at End of Life',
    category: 'Security',
    description:
      'Evaluates for the presence of Splunk-built apps that have reached end of life.',
    failureText:
      'Found one or more apps that have reached end of life.',
    suggestedAction: 'Uninstall these apps.',
    search: `| rest /services/apps/local splunk_server=*
| table title, label, author, version, splunk_server
| eval split_version = split(version, ".")
| eval installed_major = mvindex(split_version, 0)
| eval installed_minor = mvindex(split_version, 1)
| lookup splunk-upgrade-readiness-checks-installed-apps title
| search check_eol_apps=*
| eval status=if(check_eol_apps="TRUE","non-conforming","conforming")
| eval severity_level = if(status="conforming","0", "2")
| rename splunk_server AS instance`,
    tags: ['app_compatibility', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'known_outdated_splunk_built_app_versions',
    title: 'Known Outdated Splunk-Built App Versions',
    category: 'Security',
    description:
      'Evaluates for compatibility issues between certain Splunk-built apps and upcoming Splunk platform versions.',
    failureText:
      'Found one or more apps that are incompatible with an upcoming version of the Splunk platform.',
    suggestedAction:
      'Update these apps to at least the indicated version, and ideally to the latest version.',
    search: `| rest /services/apps/local splunk_server=*
| table title, label, author, version, splunk_server
| eval split_version = split(version, ".")
| eval installed_major = mvindex(split_version, 0)
| eval installed_minor = mvindex(split_version, 1)
| eval installed_patch = mvindex(split_version, 2)
| lookup splunk-upgrade-readiness-checks-installed-apps title
| eval status=if((installed_major<check_major) OR (installed_major=check_major AND installed_minor<check_minor),"non-conforming","conforming")
| eval severity_level = if(status=="conforming", "0", "2")
| rename splunk_server AS instance`,
    tags: ['app_compatibility', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'fips_incompatible_apps',
    title: 'FIPS-Incompatible Splunk-Built Apps',
    category: 'Security',
    description:
      'Evaluates for the presence of apps that are not compatible with Splunk when it runs in FIPS mode.',
    failureText:
      'Found one or more apps that are known to be incompatible with the Splunk platform when it runs in FIPS mode.',
    suggestedAction: 'Uninstall these apps.',
    search: `| rest /services/apps/local splunk_server=*
| join splunk_server type=outer [| rest /services/server/info splunk_server=* | fields splunk_server fips_mode]
| lookup splunk-upgrade-readiness-checks-installed-apps title
| search check_fips_incompatible_app=*
| eval status=if(check_fips_incompatible_app=="TRUE", "non-conforming", "conforming")
| eval severity_level = if(status=="conforming", "0","2")
| rename splunk_server AS instance`,
    tags: ['app_compatibility', 'splunk_10_0', 'fips_140_3'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'python_313_incompatible',
    title: 'Apps Not Compatible with Python 3.13',
    category: 'Security',
    description:
      'Evaluates for private and third-party apps not configured as compatible with Python 3.13. Excludes Splunk-managed apps.',
    failureText:
      'Found one or more private or third-party apps that are not configured as compatible with version 3.13 of the Python interpreter.',
    suggestedAction:
      'Contact the app developer for an updated version of the app that is compatible with Python version 3.13.',
    search: `| rest /servicesNS/-/-/configs/conf-commands splunk_server=* count=0
| append [| rest /servicesNS/-/-/configs/conf-inputs splunk_server=* count=0]
| rename "eai:acl.app" as appid
| search (python.required=* OR python.version=*) NOT python.required=*3.13* NOT python.required=*latest*
| dedup appid splunk_server
| join appid splunk_server type=inner [| rest /services/apps/local splunk_server=* | rename title as appid | table appid splunk_server author]
| eval app_category=case(match(author, "(?i)^splunk"), "splunk_managed_excluded", true(), "third_party")
| eval severity_level = if(app_category="splunk_managed_excluded", 0, 2)
| where severity_level > 0
| rename splunk_server AS instance`,
    tags: ['apps', 'splunk_enterprise_10_4'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'splunk_web_custom_rest_endpoints',
    title: 'Splunk Web Custom REST Endpoints',
    category: 'Security',
    description:
      'Evaluates for the presence of Splunk Web custom REST endpoints in private Splunk apps.',
    failureText:
      'Found at least one Splunk app that uses Splunk Web custom REST endpoints.',
    suggestedAction:
      'Review the apps on this instance that use Splunk Web custom REST endpoints and confirm that they are compatible with Python version 3.13 before upgrading to Splunk Enterprise version 10.2.',
    search: `| rest /services/apps/local splunk_server=*
| search core=0
| rename title AS app_name
| join type=inner splunk_server app_name
    [ | rest splunk_server=* /servicesNS/-/-/configs/conf-web search="eai:acl.app=*"
    | search title="endpoint:*"
    | rename "eai:acl.app" AS app_name
    | table splunk_server app_name title ]
| eval metric="This private app defines a Splunk Web custom endpoint stanza in web.conf: " . app_name
| eval severity_level=1
| rename splunk_server AS instance`,
    tags: ['apps', 'splunk 10.2'],
    source: 'health_assistant',
    status: 'unknown',
  },

  // ─── UPGRADE READINESS ───────────────────────────────────────────────────
  {
    id: 'deprecated_duo_traditional_prompt_check',
    title: 'Removed Support for Duo Traditional Prompt',
    category: 'Upgrade Readiness',
    description:
      'Evaluates for a multifactor authentication configuration that uses Duo Traditional Prompt, which relies on the deprecated SHA1 algorithm.',
    failureText:
      'Found that this instance uses Duo Traditional Prompt for multifactor authentication.',
    suggestedAction:
      'Reconfigure the instance to use Duo Universal Prompt for multifactor authentication.',
    search: `| rest splunk_server=* /services/admin/Duo-MFA
| eval affected = case(isnull(universalPrompt) OR lower(universalPrompt) IN ("false","0"), 1, 1==1, 0)
| where affected=1
| eval severity_level=2
| rename splunk_server as instance`,
    tags: ['authentication', 'security', 'splunk_10_4'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'deprecated_sha1_saml_check',
    title: 'Removed Support for SHA-1 Signed Certificates',
    category: 'Upgrade Readiness',
    description:
      'Evaluates the SAML authentication settings for presence of a configuration using only SHA1 signature or digest algorithms without any SHA-256/384/512 alternatives.',
    failureText:
      'Found a configuration in the SAML settings that uses an unsupported SHA1 signature/digest algorithm with no alternative SHA algorithms present.',
    suggestedAction:
      'Update the signatureAlgorithm, inboundSignatureAlgorithm, and inboundDigestMethod settings to use SHA-256 or stronger algorithms.',
    search: `| rest splunk_server=* /services/configs/conf-authentication
| eval sig = lower(coalesce(signatureAlgorithm,""))
| eval in_sig = lower(coalesce(inboundSignatureAlgorithm,""))
| eval in_dig = lower(coalesce(inboundDigestMethod,""))
| eval affected = case(
    (like(sig,"%sha1%") OR like(sig,"%rsa-sha1%")) AND NOT like(sig,"%sha256%") AND NOT like(sig,"%sha384%"), 1,
    (like(in_sig,"%sha1%")) AND NOT like(in_sig,"%sha256%") AND NOT like(in_sig,"%sha384%"), 1,
    1=1, 0)
| eval severity_level=case(affected=1, 3, true(), 0)
| where affected=1
| rename splunk_server as instance`,
    tags: ['authentication', 'security', 'splunk_10_4'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'deprecated_hdr_check',
    title: 'Presence of Hadoop Data Roll',
    category: 'Upgrade Readiness',
    description:
      'Evaluates for the presence of Hadoop Data Roll, a deprecated feature in Splunk 10.0.',
    failureText:
      'Detected the presence of Hadoop Data Roll, which is a deprecated feature. If you upgrade to version 10.0, Hadoop Data Roll is turned off by default.',
    suggestedAction:
      'When possible, migrate off Hadoop Data Roll and use other indexed data archiving options. To continue using this feature, remain on Splunk Enterprise version 9.4 or earlier.',
    search: `| rest splunk_server=* /services/data/vix-providers
| search NOT vix.hadoop_data_roll IN (1 t true y yes)
| stats count by splunk_server
| eval severity_level=if(count>0,2,0)
| fields splunk_server severity_level`,
    docLink: 'https://quickdraw.splunk.com/redirect/?product=Splunk&location=learnmore.archive.data&version=10.0.0',
    tags: ['splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'incomplete_app_kv_store_settings_check',
    title: 'Incomplete KV Store TLS Settings',
    category: 'Upgrade Readiness',
    description:
      'Evaluates whether TLS configurations for KV Store in the [kvstore] stanza of server.conf are partially defined, which could cause connectivity issues after upgrade to Splunk Enterprise 10.4.',
    failureText:
      'Found a partially-defined configuration for network connections for KV Store over TLS. This incomplete configuration could cause KV Store to fail after an upgrade to Splunk Enterprise version 10.4.',
    suggestedAction:
      'Review the TLS-related settings in the [kvstore] stanza before starting an upgrade to Splunk Enterprise 10.4. Either remove partial settings to fall back to [sslConfig], or complete the configuration.',
    search: `| rest splunk_server=* /services/configs/conf-server/kvstore
| eval hasServerCert=if(isnotnull(serverCert),1,0)
| eval hasSslPassword=if(isnotnull(sslPassword),1,0)
| eval hasVerifyTrue=if(lower(trim(coalesce(sslVerifyServerCert,""))) IN ("true","1"),1,0)
| eval hasCa=if(isnotnull(caCertPath) OR isnotnull(caCertFile),1,0)
| eval hasAny=if(hasServerCert=1 OR hasSslPassword=1 OR hasVerifyTrue=1 OR hasCa=1,1,0)
| eval readiness=case(hasAny=0, "OK", hasServerCert=1 AND hasSslPassword=1 AND hasCa=1, "OK", true(), "NOT_OK")
| eval severity_level=case(readiness="OK", 0, true(), 3)
| table severity_level readiness`,
    tags: ['splunk_10_4', 'kvstore'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'mongodb_version_in_acceptable_range_check_splunk_10_0',
    title: 'MongoDB Version for Splunk 10.0 (requires 4.2)',
    category: 'Upgrade Readiness',
    description:
      'Evaluates whether the MongoDB version supporting KV Store is at the required level of 4.2 before upgrading to Splunk Enterprise 10.0.',
    failureText:
      'The version of MongoDB that runs alongside this Splunk platform instance was found to be below the required 4.2.',
    suggestedAction:
      'Confirm that MongoDB is at version 4.2 or higher before you upgrade to Splunk Enterprise version 10.0.',
    search: `| rest splunk_server=* services/kvstore/version
| fields splunk_server, status.version
| rename splunk_server AS instance, status.version AS metric
| eval metric = substr(metric, 0, 3)
| eval severity_level = case( metric="4.2" OR metric="7.0", 0, true(), 2)
| table instance, metric, severity_level`,
    tags: ['splunk_10_0', 'kvstore'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'mongodb_version_in_acceptable_range_check_splunk_10_4',
    title: 'MongoDB Version for Splunk 10.4 (requires 7.0)',
    category: 'Upgrade Readiness',
    description:
      'Evaluates whether the MongoDB version supporting KV Store is at the required level of 7.0 or higher before upgrading to Splunk Enterprise 10.4.',
    failureText:
      'Found that the version of MongoDB that runs on this Splunk platform instance is below the required minimum of 7.',
    suggestedAction:
      'Confirm that MongoDB is at version 7 or higher before you upgrade to Splunk Enterprise version 10.4.',
    search: `| rest splunk_server=* services/kvstore/version
| fields splunk_server, status.version
| rename splunk_server AS instance, status.version AS metric
| eval metric = substr(metric, 0, 3)
| eval severity_level = case( metric="7.0" OR metric="8.0", 0, true(), 2)
| table instance, metric, severity_level`,
    tags: ['splunk_10_4', 'kvstore'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'system_python_version_in_acceptable_range_check',
    title: 'Python Version Usage',
    category: 'Upgrade Readiness',
    description:
      'Evaluates the current Python runtime environment. Marks as Critical if any instance is not configured to force usage of Python v3.9.',
    failureText:
      'One or more Splunk instances are not using the Python 3.9 runtime environment.',
    suggestedAction:
      'Set "python.version=force_python3" in server.conf to force usage of Python v3.9 on Splunk Enterprise 9.3.x or 9.4.x. Splunk Enterprise 10.0+ uses Python v3.9 by default.',
    search: `| rest splunk_server=* services/configs/conf-server
| fields splunk_server, python.version
| join type=left splunk_server [| rest splunk_server=* /services/server/info | fields splunk_server version]
| rename python.version AS python_version
| eval version = split(version, ".")
| eval major = mvindex(version, 0)
| eval minor = mvindex(version, 1)
| eval severity_level = case(
    (major >= 10 OR (major = 9 AND minor >= 3)) AND python_version="force_python3", 0,
    true(), 3)
| rename splunk_server AS instance`,
    tags: ['configuration', 'splunk_10_0'],
    source: 'health_assistant',
    status: 'unknown',
  },
  {
    id: 'known_outdated_splunk_built_app_versions_for_fips',
    title: 'Known Outdated Splunk-Built App Versions for FIPS',
    category: 'Upgrade Readiness',
    description:
      'Evaluates for Splunk-built apps with installed versions incompatible with Splunk when running in FIPS mode.',
    failureText:
      "Found one or more apps whose installed versions are incompatible with the Splunk platform when it runs in FIPS mode.",
    suggestedAction:
      'Update detected apps to at least the indicated version, and ideally to the latest version.',
    search: `| rest /services/apps/local splunk_server=*
| join splunk_server type=outer [| rest /services/server/info splunk_server=* | fields splunk_server fips_mode]
| lookup upgrade_readiness_app_checks.csv title
| search check_fips_compatible_app_version=* fips_mode=1
| where (installed_major<check_major) OR (installed_major=check_major AND installed_minor<check_minor)
| eval severity_level = "2"
| rename splunk_server AS instance`,
    tags: ['app_compatibility', 'splunk_10_0', 'fips_140_3'],
    source: 'health_assistant',
    status: 'unknown',
  },
  // ── PS Technical Assessment ──────────────────────────────────────────────
  {
    id: 'ps_license_utilization',
    title: 'License Utilization',
    category: 'Splunk Miscellaneous',
    description: 'Checks daily license usage against licensed volume. Usage above 90% indicates risk of license violation.',
    failureText: 'Daily license usage exceeds 90% of licensed capacity.',
    suggestedAction: 'Review indexing volume, identify high-volume sourcetypes, consider license expansion or data reduction.',
    search: `| rest /services/licenser/usage/license_usage splunk_server=local
| eval pct = round(slaves_usage_bytes / quota * 100, 1)
| eval severity_level = case(pct >= 100, 3, pct >= 90, 2, pct >= 75, 1, true(), 0)
| fields pct severity_level`,
    tags: ['license', 'capacity'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_search_concurrency',
    title: 'Search Concurrency Utilization',
    category: 'Data Search',
    description: 'Checks whether the number of concurrent searches is approaching or exceeding configured limits.',
    failureText: 'Search concurrency is at or above the configured maximum, causing search queuing.',
    suggestedAction: 'Review and tune limits.conf: max_searches_per_cpu, max_rt_search_multiplier. Consider adding search capacity.',
    search: `earliest=-1h index=_internal sourcetype=scheduler savedsearch_name=* status=*
| stats count by status
| appendcols [| rest /services/server/info splunk_server=local | fields numberOfCores]
| eval severity_level = 0
| fields severity_level`,
    tags: ['search', 'performance', 'concurrency'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_index_retention_check',
    title: 'Index Retention Configuration',
    category: 'Data Indexing',
    description: 'Verifies all indexes have explicit retention policies (frozenTimePeriodInSecs) configured rather than relying on defaults.',
    failureText: 'One or more indexes are using default retention settings, which may not meet data governance requirements.',
    suggestedAction: 'Define explicit frozenTimePeriodInSecs and maxTotalDataSizeMB for all indexes in indexes.conf.',
    search: `| rest /services/data/indexes splunk_server=local
| search disabled=0 isInternal=0
| eval using_default = if(frozenTimePeriodInSecs == 188697600, 1, 0)
| stats count(eval(using_default=1)) AS default_count, count AS total
| eval severity_level = if(default_count > 0, 1, 0)
| fields severity_level default_count total`,
    tags: ['indexes', 'retention', 'governance'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_forwarder_connectivity',
    title: 'Forwarder Connectivity',
    category: 'Data Collection',
    description: 'Checks for forwarders that have not sent data in the last 24 hours, indicating connectivity issues.',
    failureText: 'One or more forwarders have not communicated with the indexer in the last 24 hours.',
    suggestedAction: 'Investigate network connectivity, Splunk forwarder service status, and firewall rules on affected hosts.',
    search: `earliest=-24h index=_internal sourcetype=splunkd group=tcpin_connections
| stats max(_time) AS last_seen by hostname
| eval hours_silent = round((now() - last_seen) / 3600, 1)
| eval severity_level = case(hours_silent > 24, 3, hours_silent > 12, 2, hours_silent > 6, 1, true(), 0)
| stats max(severity_level) AS severity_level`,
    tags: ['forwarders', 'connectivity', 'data_collection'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_hot_bucket_age',
    title: 'Hot Bucket Age',
    category: 'Data Indexing',
    description: 'Checks for hot buckets older than 7 days, which may indicate indexing issues or misconfigured rollover settings.',
    failureText: 'One or more hot buckets are older than 7 days. This can indicate stuck buckets or misconfigured maxHotSpanSecs.',
    suggestedAction: 'Check maxHotSpanSecs and maxDataSize in indexes.conf. Run dbinspect to identify stuck hot buckets.',
    search: `| dbinspect index=* state=hot
| eval age_days = round((now() - startEpoch) / 86400, 1)
| eval severity_level = case(age_days > 14, 3, age_days > 7, 2, true(), 0)
| stats max(severity_level) AS severity_level`,
    tags: ['indexing', 'buckets', 'performance'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_deployment_server_clients',
    title: 'Deployment Server Client Health',
    category: 'Data Collection',
    description: 'Checks whether deployment server clients have checked in recently.',
    failureText: 'Deployment server clients are not checking in, indicating potential configuration management issues.',
    suggestedAction: 'Verify network access from clients to deployment server on port 8089. Check deploymentclient.conf on affected hosts.',
    search: `earliest=-24h index=_internal sourcetype=splunkd component=DS
| stats count by host
| eval severity_level = if(count > 0, 0, 1)
| stats max(severity_level) AS severity_level`,
    tags: ['deployment_server', 'configuration_management'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_props_transforms_errors',
    title: 'Props/Transforms Configuration Errors',
    category: 'Data Collection',
    description: 'Detects errors related to props.conf and transforms.conf that indicate misconfigured field extractions or event processing.',
    failureText: 'Errors found in props.conf or transforms.conf configuration. Data may not be parsed correctly.',
    suggestedAction: 'Review btool output: `splunk btool props list --debug` and fix any invalid stanzas or regex errors.',
    search: `earliest=-24h index=_internal sourcetype=splunkd (component=JsonParser OR component=LineBreaker OR component=DateParser) log_level=ERROR
| stats count AS error_count
| eval severity_level = case(error_count > 100, 3, error_count > 10, 2, error_count > 0, 1, true(), 0)
| fields severity_level error_count`,
    tags: ['configuration', 'parsing', 'props', 'transforms'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_kvstore_replication_lag',
    title: 'KV Store Replication Lag',
    category: 'Splunk Miscellaneous',
    description: 'Checks KV Store replication lag between cluster members. High lag indicates potential data loss risk.',
    failureText: 'KV Store replication lag detected. Members are not in sync.',
    suggestedAction: 'Check KV Store health via Monitoring Console. Review mongod.log for replication errors. Consider restarting KV Store.',
    search: `| rest /services/server/info splunk_server=*
| eval severity_level = if(kvStoreStatus == "ready", 0, 2)
| stats max(severity_level) AS severity_level`,
    tags: ['kv_store', 'replication', 'high_availability'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_search_peer_health',
    title: 'Search Peer Health',
    category: 'Data Search',
    description: 'Verifies all configured search peers (distributed search) are reachable and responding.',
    failureText: 'One or more search peers are unreachable or in a degraded state.',
    suggestedAction: 'Check network connectivity to the peer, verify splunkd is running, and review search peer configuration in distsearch.conf.',
    search: `| rest /services/search/distributed/peers splunk_server=local
| eval severity_level = case(status == "Up", 0, status == "Down", 3, true(), 2)
| stats max(severity_level) AS severity_level`,
    tags: ['distributed_search', 'search_peers'],
    source: 'ps_assessment',
    status: 'unknown',
  },
  {
    id: 'ps_index_disk_usage',
    title: 'Index Disk Usage',
    category: 'Data Indexing',
    description: 'Checks disk usage of indexes relative to their configured maximum size. Indexes at 90%+ capacity risk data loss from premature freezing.',
    failureText: 'One or more indexes are at or above 90% of their configured maximum size.',
    suggestedAction: 'Increase maxTotalDataSizeMB, add storage capacity, or reduce retention period. Review and optimize highest-volume indexes.',
    search: `| rest /services/data/indexes splunk_server=local
| search disabled=0
| eval pct_used = round(currentDBSizeMB / maxTotalDataSizeMB * 100, 1)
| eval severity_level = case(pct_used >= 100, 3, pct_used >= 90, 2, pct_used >= 75, 1, true(), 0)
| stats max(severity_level) AS severity_level`,
    tags: ['indexes', 'disk', 'capacity'],
    source: 'ps_assessment',
    status: 'unknown',
  },
];

export const getChecksByCategory = (category: Category): HealthCheck[] =>
  checks.filter((c) => c.category === category);

export const getCategorySummary = () => {
  return CATEGORIES.filter((c) => c !== 'Overview').map((cat) => {
    const catChecks = getChecksByCategory(cat);
    return {
      category: cat,
      total: catChecks.length,
      unknown: catChecks.filter((c) => c.status === 'unknown').length,
      pass: catChecks.filter((c) => c.status === 'pass').length,
      fail: catChecks.filter((c) => c.status === 'fail').length,
      warn: catChecks.filter((c) => c.status === 'warn').length,
      info: catChecks.filter((c) => c.status === 'info').length,
    };
  });
};
