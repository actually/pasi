# Framework configuration options
_var_dir="CHANGEME"
pid_file = _var_dir + "run/pasi-dev.pid"
out_err_log = _var_dir + "logs/dev-outerr.log"
log_file = _var_dir + "logs/dev-logging.log"
log_format = '%(asctime)s %(levelname)s %(message)s'

global_log_level = "DEBUG"
log_levels = {"test" : "DEBUG"}

# Application specific config options
soap_port = 11667
admin_user = "CHANGEME"
admin_client = "CHANGEME"
valid_p4_ports = ["SERVER1:PORT1","SERVER2:PORT2"]

# Don't let PASI fiddle with these on the p4 server
protected_users = [admin_user]
protected_groups = []

# Clients will need to pass an auth token to the server
token = "CHANGEME"