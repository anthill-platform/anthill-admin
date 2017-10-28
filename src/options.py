
from common.options import define

# Main

define("host",
       default="http://localhost:9500",
       help="Public hostname of this service",
       type=str)

define("listen",
       default="port:9500",
       help="Socket to listen. Could be a port number (port:N), or a unix domain socket (unix:PATH)",
       type=str)

define("name",
       default="admin",
       help="Service short name. User to discover by discovery service.",
       type=str)

# Regular cache

define("cache_host",
       default="127.0.0.1",
       help="Location of a regular cache (redis).",
       group="cache",
       type=str)

define("cache_port",
       default=6379,
       help="Port of regular cache (redis).",
       group="cache",
       type=int)

define("cache_db",
       default=8,
       help="Database of regular cache (redis).",
       group="cache",
       type=int)

define("cache_max_connections",
       default=500,
       help="Maximum connections to the regular cache (connection pool).",
       group="cache",
       type=int)