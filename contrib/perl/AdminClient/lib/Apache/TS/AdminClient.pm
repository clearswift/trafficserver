#
package Apache::TS::AdminClient;

use warnings;
use strict;

require 5.006;

use Carp;
use IO::Socket::UNIX;
use IO::Select;
our $VERSION = "0.01";

#
# Constructor
#
sub new {
  my $class = shift @_;
  my $self = {};
  my %args = @_;

  $self->{_socket_path} = $args{socket_path} || "/usr/local/var/trafficserver/cli"; # TODO: fix on install
  $self->{_socket} = undef;

  if ( (! -r $self->{_socket_path}) or (! -w $self->{_socket_path}) or (! -S $self->{_socket_path}) ) {
    croak "Unable to open $self->{_socket_path} for reads or writes";
    # see croak in "sub open_socket()" for other source of carp errors
  }

  $self->{_select} = IO::Select->new();
  bless $self, $class;

  $self->open_socket();

  return $self;
}

#
# Destructor
#
sub DESTROY {
  my $self = shift;
  return $self->close_socket();
}


#
# Open the socket (Unix domain)
#
sub open_socket {
  my $self = shift;
  my %args = @_;

  if (defined($self->{_socket})) {
    if ($args{force} || $args{reopen}) {
      $self->close_socket();
    } else {
      return undef ;
    }
  }


  $self->{_socket} = IO::Socket::UNIX->new(Type => SOCK_STREAM,
                                          Peer => $self->{_socket_path}) or croak ("Error opening socket - $@");

  return undef unless defined($self->{_socket});
  $self->{_select}->add($self->{_socket});

  return $self;
}

sub close_socket {
  my $self = shift;

  # if socket doesn't exist, return as there's nothing to do.
  return unless defined($self->{_socket});

  # gracefully close socket.
  $self->{_select}->remove($self->{_socket});
  $self->{_socket}->close();
  $self->{_socket} = undef;

  return $self; 
}


#
# Get (read) a stat out of the local manager. Note that the assumption is
# that you are calling this with an existing stats "name".
#
sub get_stat {
  my $self = shift;
  my $stat = shift;
  my $res = "";
  my $max_read_attempts = 25;

  return undef unless defined($self->{_socket});

  return undef unless $self->{_select}->can_write(10);
  $self->{_socket}->print("b get $stat\0");
  
  while ($res eq "") {
    return undef if ($max_read_attempts-- < 0);
    return undef unless $self->{_select}->can_read(10);

    my $status = $self->{_socket}->sysread($res, 1024);
    return undef unless defined($status) || ($status == 0);

    $res =~ s/\0+$//;
    $res =~ s/^\0+//;
  }

  my @parts = split(/;/, $res);

  return undef unless (scalar(@parts) == 3);
  return $parts[2] if ($parts[0] eq "1");
  return undef;
}

1;

__END__

#-=-=-=-=-=-=-=-= Give us some POD please =-=-=-=-=-=-=-=- 

=head1 NAME:

Apache::TS::AdminClient - a perl interface to the statistics and configuration settings stored within Apache Traffic Server.

=head1 SYNOPSIS

  #!/usr/bin/perl
  use Apache::TS::AdminClient;

  my $cli = Apache::TS::AdminClient->new(%input);
  my $string = $cli->get_stat("proxy.config.product_company");
  print "$string\n";


=head1 DESCRIPTION:

AdminClient opens a TCP connection to a unix domain socket on local disk.  When the connection is established, 
AdminClient will write requests to the socket and wait for Apache Traffic Server to return a response.  Valid 
request strings can be found in RecordsConfig.cc which is included with Apache Traffic Server source.  
A list of valid request strings are included with this documentation, but this included list may not be complete
as future releases of Apache Traffic Server may include new request strings or remove existing ones.  

=head1 OPTIONS

=head2 socket_path

When the object is created for this module, it assumes the 'Unix Domain Socket' is at the default location of 
B<'/usr/local/var/trafficserver/cli'>  This can be changed when creating the object by setting B<'socket_path'>. For example: 

  my $cli = AdminClient->new(socket_path=> "/dev/null");

would make the module look for the 'Unix Domain Socket' at /dev/null.  Of course this isn't a realistic example, but can be used when
modified appropiately.  

=head2 traffic_line

There is a command line tool included with Apache Traffic Server called traffic_line which overlaps with this module.  traffic_line 
can be used to read and write statistics or config settings that this module can.  Hence if you don't want to write a perl one-liner to 
get to this information, traffic_line is your tool.

=head1 List of Request Strings

The Apache Traffic Server Administration Manual will explain what these strings represent.  (http://trafficserver.apache.org/docs/)

 proxy.config.aaa.billing.event_file_location
 proxy.config.aaa.billing.install_directory
 proxy.config.aaa.billing.machine_name
 proxy.config.aaa.billing.reporting_interval
 proxy.config.aaa.hashtable.size
 proxy.config.aaa.radius.acct_port
 proxy.config.aaa.radius.auth_port
 proxy.config.aaa.radius.database_path
 proxy.config.aaa.radius.is_proxy
 proxy.config.aaa.radius.log_path
 proxy.config.aaa.radius.max_retries
 proxy.config.aaa.radius.min_timeout
 proxy.config.aaa.radius.radius_server_acct_port
 proxy.config.aaa.radius.radius_server_auth_port
 proxy.config.aaa.radius.radius_server_ip
 proxy.config.aaa.radius.radius_server_key
 proxy.config.accept_threads
 proxy.config.admin.access_control_file
 proxy.config.admin.admin_password
 proxy.config.admin.admin_user
 proxy.config.admin.advanced_ui
 proxy.config.admin.autoconf.localhost_only
 proxy.config.admin.autoconf.pac_filename
 proxy.config.admin.autoconf_port
 proxy.config.admin.autoconf.wpad_filename
 proxy.config.admin.basic_auth
 proxy.config.admin.cli_enabled
 proxy.config.admin.cli_path
 proxy.config.admin.cli_port
 proxy.config.admin.html_doc_root
 proxy.config.admin.ip_allow.filename
 proxy.config.admin.lang_dict
 proxy.config.admin.load_factor
 proxy.config.admin.log_mgmt_access
 proxy.config.admin.log_resolve_hostname
 proxy.config.admin.number_config_bak
 proxy.config.admin.overseer_mode
 proxy.config.admin.overseer_port
 proxy.config.admin.session
 proxy.config.admin.session.timeout
 proxy.config.admin.ssl_cert_file
 proxy.config.admin.ui_refresh_rate
 proxy.config.admin.user_id
 proxy.config.admin.use_ssl
 proxy.config.admin.web_interface_port
 proxy.config.alarm.abs_path
 proxy.config.alarm.bin
 proxy.config.alarm_email
 proxy.config.alarm.script_runtime
 proxy.config.auth.cache.filename
 proxy.config.auth.cache.path
 proxy.config.auth.cache.size
 proxy.config.auth.cache.storage_size
 proxy.config.auth.convert_bin
 proxy.config.auth.convert_filter_to_policy
 proxy.config.auth.enabled
 proxy.config.auth.password_file_path
 proxy.config.auth.threads
 proxy.config.bandwidth_mgmt.filename
 proxy.config.bin_path
 proxy.config.body_factory.enable_customizations
 proxy.config.body_factory.enable_logging
 proxy.config.body_factory.response_suppression_mode
 proxy.config.body_factory.template_sets_dir
 proxy.config.cache.agg_write_backlog
 proxy.config.cache.aio_sleep_time
 proxy.config.cache.alt_rewrite_max_size
 proxy.config.cache.check_disk_idle
 proxy.config.cache.control.filename
 proxy.config.cache.dir.sync_frequency
 proxy.config.cache.enable_checksum
 proxy.config.cache.enable_read_while_writer
 proxy.config.cache.hostdb.disable_reverse_lookup
 proxy.config.cache.hostdb.sync_frequency
 proxy.config.cache.hosting_filename
 proxy.config.cache.ip_allow.filename
 proxy.config.cache.limits.http.max_alts
 proxy.config.cache.max_agg_delay
 proxy.config.cache.max_disk_errors
 proxy.config.cache.max_doc_size
 proxy.config.cache.min_average_object_size
 proxy.config.cache.partition_filename
 proxy.config.cache.permit.pinning
 proxy.config.cache.ram_cache_cutoff
 proxy.config.cache.ram_cache_mixt_cutoff
 proxy.config.cache.ram_cache.size
 proxy.config.cache.select_alternate
 proxy.config.cache.storage_filename
 proxy.config.cache.threads_per_disk
 proxy.config.cache.url_hash_method
 proxy.config.cache.vary_on_user_agent
 proxy.config.cli_binary
 proxy.config.cluster.cluster_configuration
 proxy.config.cluster.cluster_load_clear_duration
 proxy.config.cluster.cluster_load_exceed_duration
 proxy.config.cluster.cluster_port
 proxy.config.cluster.delta_thresh
 proxy.config.cluster.enable_monitor
 proxy.config.cluster.ethernet_interface
 proxy.config.cluster.load_compute_interval_msecs
 proxy.config.cluster.load_monitor_enabled
 proxy.config.cluster.log_bogus_mc_msgs
 proxy.config.cluster.mc_group_addr
 proxy.config.cluster.mcport
 proxy.config.cluster.mc_ttl
 proxy.config.cluster.monitor_interval_secs
 proxy.config.cluster.msecs_per_ping_response_bucket
 proxy.config.cluster.peer_timeout
 proxy.config.cluster.periodic_timer_interval_msecs
 proxy.config.cluster.ping_history_buf_length
 proxy.config.cluster.ping_latency_threshold_msecs
 proxy.config.cluster.ping_response_buckets
 proxy.config.cluster.ping_send_interval_msecs
 proxy.config.cluster.receive_buffer_size
 proxy.config.cluster.rpc_cache_cluster
 proxy.config.cluster.rsport
 proxy.config.cluster.send_buffer_size
 proxy.config.cluster.sock_option_flag
 proxy.config.cluster.startup_timeout
 proxy.config.config_dir
 proxy.config.connection_collapsing.hashtable_enabled
 proxy.config.connection_collapsing.revalidate_window_period
 proxy.config.connection_collapsing.rww_wait_time
 proxy.config.content_filter.filename
 proxy.config.cop.core_signal
 proxy.config.cop.linux_min_memfree_kb
 proxy.config.cop.linux_min_swapfree_kb
 proxy.config.cop_name
 proxy.config.core_limit
 proxy.config.diags.action.enabled
 proxy.config.diags.action.tags
 proxy.config.diags.debug.enabled
 proxy.config.diags.debug.tags
 proxy.config.diags.output.alert
 proxy.config.diags.output.debug
 proxy.config.diags.output.diag
 proxy.config.diags.output.emergency
 proxy.config.diags.output.error
 proxy.config.diags.output.fatal
 proxy.config.diags.output.note
 proxy.config.diags.output.status
 proxy.config.diags.output.warning
 proxy.config.diags.show_location
 proxy.config.dns.failover_number
 proxy.config.dns.failover_period
 proxy.config.dns.lookup_timeout
 proxy.config.dns.max_dns_in_flight
 proxy.config.dns.nameservers
 proxy.config.dns.proxy.enabled
 proxy.config.dns.proxy_port
 proxy.config.dns.retries
 proxy.config.dns.round_robin_nameservers
 proxy.config.dns.search_default_domains
 proxy.config.dns.splitdns.def_domain
 proxy.config.dns.splitDNS.enabled
 proxy.config.dns.splitdns.filename
 proxy.config.dns.url_expansions
 proxy.config.dump_mem_info_frequency
 proxy.config.env_prep
 proxy.config.exec_thread.autoconfig
 proxy.config.exec_thread.autoconfig.scale
 proxy.config.exec_thread.limit
 proxy.config.feature_set
 proxy.config.header.parse.no_host_url_redirect
 proxy.config.history_info_enabled
 proxy.config.hostdb
 proxy.config.hostdb.cluster
 proxy.config.hostdb.cluster.round_robin
 proxy.config.hostdb.fail.timeout
 proxy.config.hostdb.filename
 proxy.config.hostdb.lookup_timeout
 proxy.config.hostdb.migrate_on_demand
 proxy.config.hostdb.re_dns_on_reload
 proxy.config.hostdb.serve_stale_for
 proxy.config.hostdb.size
 proxy.config.hostdb.storage_path
 proxy.config.hostdb.storage_size
 proxy.config.hostdb.strict_round_robin
 proxy.config.hostdb.timeout
 proxy.config.hostdb.ttl_mode
 proxy.config.hostdb.verify_after
 proxy.config.http.accept_encoding_filter_enabled
 proxy.config.http.accept_encoding_filter.filename
 proxy.config.http.accept_no_activity_timeout
 proxy.config.http.anonymize_insert_client_ip
 proxy.config.http.anonymize_other_header_list
 proxy.config.http.anonymize_remove_client_ip
 proxy.config.http.anonymize_remove_cookie
 proxy.config.http.anonymize_remove_from
 proxy.config.http.anonymize_remove_referer
 proxy.config.http.anonymize_remove_user_agent
 proxy.config.http.append_xforwards_header
 proxy.config.http.auth.authenticate_session
 proxy.config.http.auth.flags
 proxy.config.http.auth.scope
 proxy.config.http.avoid_content_spoofing
 proxy.config.http.background_fill_active_timeout
 proxy.config.http.background_fill_completed_threshold
 proxy.config.http.cache.cache_responses_to_cookies
 proxy.config.http.cache.cache_urls_that_look_dynamic
 proxy.config.http.cache.enable_default_vary_headers
 proxy.config.http.cache.fuzz.min_time
 proxy.config.http.cache.fuzz.probability
 proxy.config.http.cache.fuzz.time
 proxy.config.http.cache.guaranteed_max_lifetime
 proxy.config.http.cache.guaranteed_min_lifetime
 proxy.config.http.cache.heuristic_lm_factor
 proxy.config.http.cache.heuristic_max_lifetime
 proxy.config.http.cache.heuristic_min_lifetime
 proxy.config.http.cache.http
 proxy.config.http.cache.ignore_accept_charset_mismatch
 proxy.config.http.cache.ignore_accept_encoding_mismatch
 proxy.config.http.cache.ignore_accept_language_mismatch
 proxy.config.http.cache.ignore_accept_mismatch
 proxy.config.http.cache.ignore_authentication
 proxy.config.http.cache.ignore_client_cc_max_age
 proxy.config.http.cache.ignore_client_no_cache
 proxy.config.http.cache.ignore_server_no_cache
 proxy.config.http.cache.ims_on_client_no_cache
 proxy.config.http.cache.max_open_read_retries
 proxy.config.http.cache.max_open_write_retries
 proxy.config.http.cache.max_stale_age
 proxy.config.http.cache.open_read_retry_time
 proxy.config.http.cache.open_write_retry_time
 proxy.config.http.cache.range.lookup
 proxy.config.http.cache.required_headers
 proxy.config.http.cache.vary_default_images
 proxy.config.http.cache.vary_default_other
 proxy.config.http.cache.vary_default_text
 proxy.config.http.cache.when_to_add_no_cache_to_msie_requests
 proxy.config.http.cache.when_to_revalidate
 proxy.config.http.chunking_enabled
 proxy.config.http.congestion_control.default.client_wait_interval
 proxy.config.http.congestion_control.default.congestion_scheme
 proxy.config.http.congestion_control.default.dead_os_conn_retries
 proxy.config.http.congestion_control.default.dead_os_conn_timeout
 proxy.config.http.congestion_control.default.error_page
 proxy.config.http.congestion_control.default.fail_window
 proxy.config.http.congestion_control.default.live_os_conn_retries
 proxy.config.http.congestion_control.default.live_os_conn_timeout
 proxy.config.http.congestion_control.default.max_connection
 proxy.config.http.congestion_control.default.max_connection_failures
 proxy.config.http.congestion_control.default.proxy_retry_interval
 proxy.config.http.congestion_control.default.snmp
 proxy.config.http.congestion_control.default.wait_interval_alpha
 proxy.config.http.congestion_control.enabled
 proxy.config.http.congestion_control.filename
 proxy.config.http.congestion_control.localtime
 proxy.config.http.connect_attempts_max_retries
 proxy.config.http.connect_attempts_max_retries_dead_server
 proxy.config.http.connect_attempts_rr_retries
 proxy.config.http.connect_attempts_timeout
 proxy.config.http.connect_ports
 proxy.config.http.default_buffer_size
 proxy.config.http.default_buffer_water_mark
 proxy.config.http.doc_in_cache_skip_dns
 proxy.config.http.down_server.abort_threshold
 proxy.config.http.down_server.cache_time
 proxy.config.http.enabled
 proxy.config.http.enable_http_info
 proxy.config.http.enable_http_stats
 proxy.config.http.enable_url_expandomatic
 proxy.config.http.errors.log_error_pages
 proxy.config.http.forward.proxy_auth_to_parent
 proxy.config.http.global_user_agent_header
 proxy.config.http.inktoswitch_enabled
 proxy.config.http.insert_age_in_response
 proxy.config.http.insert_request_via_str
 proxy.config.http.insert_response_via_str
 proxy.config.http.insert_squid_x_forwarded_for
 proxy.config.http.keep_alive_enabled
 proxy.config.http.keep_alive_no_activity_timeout_in
 proxy.config.http.keep_alive_no_activity_timeout_out
 proxy.config.http.keep_alive_post_out
 proxy.config.http.log_spider_codes
 proxy.config.http.negative_caching_enabled
 proxy.config.http.negative_caching_lifetime
 proxy.config.http.negative_revalidating_enabled
 proxy.config.http.negative_revalidating_lifetime
 proxy.config.http.no_dns_just_forward_to_parent
 proxy.config.http.no_origin_server_dns
 proxy.config.http.normalize_ae_gzip
 proxy.config.http.number_of_redirections
 proxy.config.http.origin_max_connections
 proxy.config.http.origin_min_keep_alive_connections
 proxy.config.http.origin_server_pipeline
 proxy.config.http.parent_proxies
 proxy.config.http.parent_proxy.connect_attempts_timeout
 proxy.config.http.parent_proxy.fail_threshold
 proxy.config.http.parent_proxy.file
 proxy.config.http.parent_proxy.per_parent_connect_attempts
 proxy.config.http.parent_proxy.retry_time
 proxy.config.http.parent_proxy_routing_enable
 proxy.config.http.parent_proxy.total_connect_attempts
 proxy.config.http.post_connect_attempts_timeout
 proxy.config.http.post_copy_size
 proxy.config.http.push_method_enabled
 proxy.config.http.quick_filter.mask
 proxy.config.http.record_heartbeat
 proxy.config.http.record_tcp_mem_hit
 proxy.config.http.redirection_enabled
 proxy.config.http.referer_default_redirect
 proxy.config.http.referer_filter
 proxy.config.http.referer_format_redirect
 proxy.config.http.request_header_max_size
 proxy.config.http.request_via_str
 proxy.config.http.response_header_max_size
 proxy.config.http.response_server_enabled
 proxy.config.http.response_server_str
 proxy.config.http.response_via_str
 proxy.config.http.router_ip
 proxy.config.http.router_port
 proxy.config.http.send_http11_requests
 proxy.config.http.server_max_connections
 proxy.config.http.server_other_ports
 proxy.config.http.server_port
 proxy.config.http.server_port_attr
 proxy.config.http.session_auth_cache_keep_alive_enabled
 proxy.config.http.share_server_sessions
 proxy.config.http.slow.log.threshold
 proxy.config.http.snarf_username_from_authorization
 proxy.config.http.ssl_ports
 proxy.config.http.streaming_connect_attempts_timeout
 proxy.config.http.transaction_active_timeout_in
 proxy.config.http.transaction_active_timeout_out
 proxy.config.http.transaction_no_activity_timeout_in
 proxy.config.http.transaction_no_activity_timeout_out
 proxy.config.http_ui_enabled
 proxy.config.http.uncacheable_requests_bypass_parent
 proxy.config.http.user_agent_pipeline
 proxy.config.http.verbose_via_str
 proxy.config.http.wuts_enabled
 proxy.config.icp.default_reply_port
 proxy.config.icp.enabled
 proxy.config.icp.icp_configuration
 proxy.config.icp.icp_interface
 proxy.config.icp.icp_port
 proxy.config.icp.lookup_local
 proxy.config.icp.multicast_enabled
 proxy.config.icp.query_timeout
 proxy.config.icp.reply_to_unknown_peer
 proxy.config.icp.stale_icp_enabled
 proxy.config.io.max_buffer_size
 proxy.config.ldap.auth.bound_attr_search
 proxy.config.ldap.auth.bypass.enabled
 proxy.config.ldap.auth.enabled
 proxy.config.ldap.auth.multiple.ldap_servers.config.file
 proxy.config.ldap.auth.multiple.ldap_servers.enabled
 proxy.config.ldap.auth.periodic.timeout.interval
 proxy.config.ldap.auth.purge_cache_on_auth_fail
 proxy.config.ldap.auth.query.timeout
 proxy.config.ldap.auth.redirect_url
 proxy.config.ldap.auth.ttl_value
 proxy.config.ldap.cache.filename
 proxy.config.ldap.cache.size
 proxy.config.ldap.cache.storage_path
 proxy.config.ldap.cache.storage_size
 proxy.config.ldap.proc.ldap.attribute.name
 proxy.config.ldap.proc.ldap.attribute.value
 proxy.config.ldap.proc.ldap.base.dn
 proxy.config.ldap.proc.ldap.server.bind_dn
 proxy.config.ldap.proc.ldap.server.bind_pwd
 proxy.config.ldap.proc.ldap.server.name
 proxy.config.ldap.proc.ldap.server.port
 proxy.config.ldap.proc.ldap.uid_filter
 proxy.config.ldap.secure.bind.enabled
 proxy.config.ldap.secure.cert.db.path
 proxy.config.lm.pserver_timeout_msecs
 proxy.config.lm.pserver_timeout_secs
 proxy.config.lm.sem_id
 proxy.config.local_state_dir
 proxy.config.log2.ascii_buffer_size
 proxy.config.log2.auto_delete_rolled_files
 proxy.config.log2.collation_host
 proxy.config.log2.collation_host_tagged
 proxy.config.log2.collation_max_send_buffers
 proxy.config.log2.collation_port
 proxy.config.log2.collation_retry_sec
 proxy.config.log2.collation_secret
 proxy.config.log2.common_log_enabled
 proxy.config.log2.common_log_header
 proxy.config.log2.common_log_is_ascii
 proxy.config.log2.common_log_name
 proxy.config.log2.config_file
 proxy.config.log2.custom_logs_enabled
 proxy.config.log2.extended2_log_enabled
 proxy.config.log2.extended2_log_header
 proxy.config.log2.extended2_log_is_ascii
 proxy.config.log2.extended2_log_name
 proxy.config.log2.extended_log_enabled
 proxy.config.log2.extended_log_header
 proxy.config.log2.extended_log_is_ascii
 proxy.config.log2.extended_log_name
 proxy.config.log2.file_stat_frequency
 proxy.config.log2.hostname
 proxy.config.log2.hosts_config_file
 proxy.config.log2.log_buffer_size
 proxy.config.log2.logfile_dir
 proxy.config.log2.logfile_perm
 proxy.config.log2.logging_enabled
 proxy.config.log2.max_entries_per_buffer
 proxy.config.log2.max_line_size
 proxy.config.log2.max_secs_per_buffer
 proxy.config.log2.max_space_mb_for_logs
 proxy.config.log2.max_space_mb_for_orphan_logs
 proxy.config.log2.max_space_mb_headroom
 proxy.config.log2.overspill_report_count
 proxy.config.log2.rolling_enabled
 proxy.config.log2.rolling_interval_sec
 proxy.config.log2.rolling_offset_hr
 proxy.config.log2.rolling_size_mb
 proxy.config.log2.sampling_frequency
 proxy.config.log2.search_log_enabled
 proxy.config.log2.search_log_filters
 proxy.config.log2.search_rolling_interval_sec
 proxy.config.log2.search_server_ip_addr
 proxy.config.log2.search_server_port
 proxy.config.log2.search_top_sites
 proxy.config.log2.search_url_filter
 proxy.config.log2.separate_host_logs
 proxy.config.log2.separate_icp_logs
 proxy.config.log2.separate_mixt_logs
 proxy.config.log2.space_used_frequency
 proxy.config.log2.squid_log_enabled
 proxy.config.log2.squid_log_header
 proxy.config.log2.squid_log_is_ascii
 proxy.config.log2.squid_log_name
 proxy.config.log2.xml_config_file
 proxy.config.log2.xml_logs_config
 proxy.config.manager_binary
 proxy.config.manager_name
 proxy.config.mixt.mp3.enabled
 proxy.config.mixt.mp3.port
 proxy.config.mixt.push.enabled
 proxy.config.mixt.push.password
 proxy.config.mixt.push.port
 proxy.config.mixt.push.verbosity
 proxy.config.mixt.rtsp_proxy_port
 proxy.config.mixt.wmtmcast.enabled
 proxy.config.net.accept_throttle
 proxy.config.net.connections_throttle
 proxy.config.net.enable_ink_disk_io
 proxy.config.net.ink_aio_write_threads
 proxy.config.net.ink_disk_io_watermark
 proxy.config.net.listen_backlog
 proxy.config.net.max_kqueue_len
 proxy.config.net.max_poll_delay
 proxy.config.net.nt.main_accept_pool_size
 proxy.config.net.os_sock_option_flag
 proxy.config.net.os_sock_recv_buffer_size
 proxy.config.net.os_sock_send_buffer_size
 proxy.config.net_snapshot_filename
 proxy.config.net.sock_mss_in
 proxy.config.net.sock_option_flag
 proxy.config.net.sock_option_flag_in
 proxy.config.net.sock_option_flag_out
 proxy.config.net.sock_recv_buffer_size
 proxy.config.net.sock_recv_buffer_size_in
 proxy.config.net.sock_recv_buffer_size_out
 proxy.config.net.sock_send_buffer_size
 proxy.config.net.sock_send_buffer_size_in
 proxy.config.net.sock_send_buffer_size_out
 proxy.config.net.tcp_accept_defer_timeout
 proxy.config.net.throttle_enabled
 proxy.config.ntlm.allow_guest_login
 proxy.config.ntlm.auth.enabled
 proxy.config.ntlm.cache.enabled
 proxy.config.ntlm.cache.filename
 proxy.config.ntlm.cache.size
 proxy.config.ntlm.cache.storage_path
 proxy.config.ntlm.cache.storage_size
 proxy.config.ntlm.cache.ttl_value
 proxy.config.ntlm.dc.fail_threshold
 proxy.config.ntlm.dc.list
 proxy.config.ntlm.dc.load_balance
 proxy.config.ntlm.dc.max_connections
 proxy.config.ntlm.dc.max_conn_time
 proxy.config.ntlm.dc.retry_time
 proxy.config.ntlm.fail_open
 proxy.config.ntlm.nt_domain
 proxy.config.ntlm.nt_host
 proxy.config.ntlm.queue_len
 proxy.config.ntlm.req_timeout
 proxy.config.output.logfile
 proxy.config.ping.npacks_to_trans
 proxy.config.ping.timeout_sec
 proxy.config.plugin.extensions_dir
 proxy.config.plugin.plugin_dir
 proxy.config.plugin.plugin_mgmt_dir
 proxy.config.prefetch.child_port
 proxy.config.prefetch.config_file
 proxy.config.prefetch.default_data_proto
 proxy.config.prefetch.default_url_proto
 proxy.config.prefetch.keepalive_timeout
 proxy.config.prefetch.max_object_size
 proxy.config.prefetch.max_recursion
 proxy.config.prefetch.prefetch_enabled
 proxy.config.prefetch.push_cached_objects
 proxy.config.prefetch.redirection
 proxy.config.prefetch.url_buffer_size
 proxy.config.prefetch.url_buffer_timeout
 proxy.config.process_manager.enable_mgmt_port
 proxy.config.process_manager.mgmt_port
 proxy.config.process_manager.timeout
 proxy.config.process_state_dump_mode
 proxy.config.product_company
 proxy.config.product_name
 proxy.config.product_vendor
 proxy.config.proxy.authenticate.basic.realm
 proxy.config.proxy_binary
 proxy.config.proxy_binary_opts
 proxy.config.proxy_name
 proxy.config.qt.digest_masquerade.enabled
 proxy.config.qt.enabled
 proxy.config.qt.live_splitter.enabled
 proxy.config.qt.media_bridge.monitor.name
 proxy.config.qt.media_bridge.monitor.port
 proxy.config.qt.media_bridge.mount_point
 proxy.config.qt.media_bridge.name
 proxy.config.qt.media_bridge.port
 proxy.config.qt.tunnel_rni_req
 proxy.config.radius.auth.enabled
 proxy.config.radius.auth.max_retries
 proxy.config.radius.auth.min_timeout
 proxy.config.radius.auth.purge_cache_on_auth_fail
 proxy.config.radius.auth.ttl_value
 proxy.config.radius.cache.size
 proxy.config.radius.cache.storage_size
 proxy.config.radius.proc.radius.primary_server.acct_port
 proxy.config.radius.proc.radius.primary_server.auth_port
 proxy.config.radius.proc.radius.primary_server.name
 proxy.config.radius.proc.radius.primary_server.shared_key
 proxy.config.radius.proc.radius.primary_server.shared_key_file
 proxy.config.radius.proc.radius.secondary_server.acct_port
 proxy.config.radius.proc.radius.secondary_server.auth_port
 proxy.config.radius.proc.radius.secondary_server.name
 proxy.config.radius.proc.radius.secondary_server.shared_key
 proxy.config.radius.proc.radius.secondary_server.shared_key_file
 proxy.config.raf.enabled
 proxy.config.raf.manager.enabled
 proxy.config.raf.manager.port
 proxy.config.raf.port
 proxy.config.raft.accept_port
 proxy.config.raft.enabled
 proxy.config.raft.proxy_version_max
 proxy.config.raft.proxy_version_min
 proxy.config.raft.server_port
 proxy.config.remap.num_remap_threads
 proxy.config.remap.use_remap_processor
 proxy.config.resource.target_maxmem_mb
 proxy.config.res_track_memory
 proxy.config.reverse_proxy.enabled
 proxy.config.reverse_proxy.oldasxbehavior
 proxy.config.rni.auth_port
 proxy.config.rni.cache_port
 proxy.config.rni.control_port
 proxy.config.rni.enabled
 proxy.config.rni.proxy_cache_dir
 proxy.config.rni.proxy_pid_path
 proxy.config.rni.proxy_port
 proxy.config.rni.proxy_restart_cmd
 proxy.config.rni.proxy_restart_interval
 proxy.config.rni.proxy_service_name
 proxy.config.rni.rpass_restart_cmd
 proxy.config.rni.rpass_watcher_enabled
 proxy.config.rni.upstream_cache_port
 proxy.config.rni.verbosity
 proxy.config.rni.watcher_enabled
 proxy.config.server_name
 proxy.config.snapshot_dir
 proxy.config.snmp.master_agent_enabled
 proxy.config.snmp.snmp_encap_enabled
 proxy.config.snmp.trap_message
 proxy.config.socks.accept_enabled
 proxy.config.socks.accept_port
 proxy.config.socks.connection_attempts
 proxy.config.socks.default_servers
 proxy.config.socks.http_port
 proxy.config.socks.per_server_connection_attempts
 proxy.config.socks.server_connect_timeout
 proxy.config.socks.server_fail_threshold
 proxy.config.socks.server_retry_time
 proxy.config.socks.server_retry_timeout
 proxy.config.socks.socks_config_file
 proxy.config.socks.socks_needed
 proxy.config.socks.socks_timeout
 proxy.config.socks.socks_version
 proxy.config.srv_enabled
 proxy.config.ssl.accelerator_required
 proxy.config.ssl.accelerator.type
 proxy.config.ssl.atalla.lib.path
 proxy.config.ssl.broadcom.lib.path
 proxy.config.ssl.CA.cert.filename
 proxy.config.ssl.CA.cert.path
 proxy.config.ssl.client.CA.cert.filename
 proxy.config.ssl.client.CA.cert.path
 proxy.config.ssl.client.cert.filename
 proxy.config.ssl.client.certification_level
 proxy.config.ssl.client.cert.path
 proxy.config.ssl.client.private_key.filename
 proxy.config.ssl.client.private_key.path
 proxy.config.ssl.client.verify.server
 proxy.config.ssl.cswift.lib.path
 proxy.config.ssl.enabled
 proxy.config.ssl.ncipher.lib.path
 proxy.config.ssl.number.threads
 proxy.config.ssl.server.cert_chain.filename
 proxy.config.ssl.server.cert.filename
 proxy.config.ssl.server.cert.path
 proxy.config.ssl.server.multicert.filename
 proxy.config.ssl.server_port
 proxy.config.ssl.server.private_key.filename
 proxy.config.ssl.server.private_key.path
 proxy.config.stack_dump_enabled
 proxy.config.start_script
 proxy.config.stat_collector.interval
 proxy.config.stat_collector.port
 proxy.config.stats.config_file
 proxy.config.stats.snap_file
 proxy.config.stats.snap_frequency
 proxy.config.stat_systemV2.max_stats_allowed
 proxy.config.stat_systemV2.num_stats_estimate
 proxy.config.syslog_facility
 proxy.config.system.memalign_heap
 proxy.config.system.mmap_max
 proxy.config.temp_dir
 proxy.config.thread.default.stacksize
 proxy.config.traffic_net.traffic_net_encryption
 proxy.config.traffic_net.traffic_net_frequency
 proxy.config.traffic_net.traffic_net_lid
 proxy.config.traffic_net.traffic_net_mode
 proxy.config.traffic_net.traffic_net_path
 proxy.config.traffic_net.traffic_net_port
 proxy.config.traffic_net.traffic_net_server
 proxy.config.traffic_net.traffic_net_uid
 proxy.config.udp.free_cancelled_pkts_sec
 proxy.config.udp.periodic_cleanup
 proxy.config.udp.send_retries
 proxy.config.update.concurrent_updates
 proxy.config.update.enabled
 proxy.config.update.force
 proxy.config.update.max_update_state_machines
 proxy.config.update.memory_use_mb
 proxy.config.update.retry_count
 proxy.config.update.retry_interval
 proxy.config.update.update_configuration
 proxy.config.url_remap.default_to_server_pac
 proxy.config.url_remap.default_to_server_pac_port
 proxy.config.url_remap.filename
 proxy.config.url_remap.pristine_host_hdr
 proxy.config.url_remap.remap_required
 proxy.config.url_remap.url_remap_mode
 proxy.config.user_name
 proxy.config.username.cache.enabled
 proxy.config.username.cache.filename
 proxy.config.username.cache.size
 proxy.config.username.cache.storage_path
 proxy.config.username.cache.storage_size
 proxy.config.vmap.addr_file
 proxy.config.vmap.down_up_timeout
 proxy.config.vmap.enabled
 proxy.config.watch_script
 proxy.config.wmt.admin_only_mcast_start
 proxy.config.wmt.asx_cache.enabled
 proxy.config.wmt.asx_rewrite.enabled
 proxy.config.wmt.chunksize_sec
 proxy.config.wmt.debug_level
 proxy.config.wmt.debug.maxgap
 proxy.config.wmt.debug_tags.enabled
 proxy.config.wmt.enabled
 proxy.config.wmt.file_attribute_mask
 proxy.config.wmt.http.enabled
 proxy.config.wmt.http.proxyonly
 proxy.config.wmt.inactivity_timeout
 proxy.config.wmt.loadhost
 proxy.config.wmt.loadpath
 proxy.config.wmt.log_http_intercept
 proxy.config.wmt.log_per_client
 proxy.config.wmt.loopback.enabled
 proxy.config.wmt.max_rexmit_memory
 proxy.config.wmt.media_bridge.livehosts
 proxy.config.wmt.media_bridge.monitor.livehosts
 proxy.config.wmt.media_bridge.monitor.name
 proxy.config.wmt.media_bridge.monitor.port
 proxy.config.wmt.media_bridge.monitor.version
 proxy.config.wmt.media_bridge.mount_point
 proxy.config.wmt.media_bridge.name
 proxy.config.wmt.media_bridge.port
 proxy.config.wmt.media_bridge.version
 proxy.config.wmt.mem_startdrop_mb
 proxy.config.wmt.ntlm.domain
 proxy.config.wmt.ntlm.host
 proxy.config.wmt.old_splitter_logging
 proxy.config.wmt.port
 proxy.config.wmt.post_wait_time
 proxy.config.wmt.prebuffering_ms
 proxy.config.wmt.prebuffering_ms_tcp
 proxy.config.wmt.proxyonly
 proxy.config.wmt.redirect.enabled
 proxy.config.wmt.tcp_backlog_behavior
 proxy.config.wmt.tcp_max_backlog_sec

=head1 LICENSE

 Simple Apache Traffic Server client object, to communicate with the local manager.

 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

=cut

#-=-=-=-=-=-=-=-= No more POD for you =-=-=-=-=-=-=-=- 
