from flask import Flask, request, jsonify, make_response, Response
import requests
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
import os
import time
import json
import logging
from cachetools import cached, TTLCache
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# HuBMAP commons
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException


# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-hubmap-auth.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config=True)
app.config.from_pyfile('app.cfg')

# Remove trailing slash / from URL base to avoid "//" caused by config with trailing slash
app.config['UUID_API_URL'] = app.config['UUID_API_URL'].strip('/')
app.config['ENTITY_API_URL'] = app.config['ENTITY_API_URL'].strip('/')

# Also remove trailing slash / for those status endpoints 
# because Flask treats urls with / as different endpoints
app.config['UUID_API_STATUS_URL'] = app.config['UUID_API_STATUS_URL'].strip('/')
app.config['ENTITY_API_STATUS_URL'] = app.config['ENTITY_API_STATUS_URL'].strip('/')
app.config['INGEST_API_STATUS_URL'] = app.config['INGEST_API_STATUS_URL'].strip('/')
app.config['SEARCH_API_STATUS_URL'] = app.config['SEARCH_API_STATUS_URL'].strip('/')
app.config['FILE_ASSETS_STATUS_URL'] = app.config['FILE_ASSETS_STATUS_URL'].strip('/')
app.config['CELLS_API_STATUS_URL'] = app.config['CELLS_API_STATUS_URL'].strip('/')
app.config['WORKSPACES_API_STATUS_URL'] = app.config['WORKSPACES_API_STATUS_URL'].strip('/')
app.config['ONTOLOGY_API_STATUS_URL'] = app.config['ONTOLOGY_API_STATUS_URL'].strip('/')
app.config['UKV_API_STATUS_URL'] = app.config['UKV_API_STATUS_URL'].strip('/')
app.config['DATA_PRODUCTS_API_STATUS_URL'] = app.config['DATA_PRODUCTS_API_STATUS_URL'].strip('/')
app.config['SCFIND_API_STATUS_URL'] = app.config['SCFIND_API_STATUS_URL'].strip('/')
app.config['SPATIALQUERY_API_STATUS_URL'] = app.config['SPATIALQUERY_API_STATUS_URL'].strip('/')

# LRU Cache implementation with per-item time-to-live (TTL) value
# with a memoizing callable that saves up to maxsize results based on a Least Frequently Used (LFU) algorithm
# with a per-item time-to-live (TTL) value
# Here we use two hours, 7200 seconds for ttl
cache = TTLCache(maxsize=app.config['CACHE_MAXSIZE'], ttl=app.config['CACHE_TTL'])

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)

####################################################################################################
## AuthHelper initialization
####################################################################################################


# Initialize AuthHelper class and ensure singleton
try:
    if AuthHelper.isInitialized() == False:
        auth_helper_instance = AuthHelper.create(app.config['GLOBUS_APP_ID'], 
                                                 app.config['GLOBUS_APP_SECRET'])

        logger.info("Initialized AuthHelper class successfully :)")
    else:
        auth_helper_instance = AuthHelper.instance()
except Exception:
    msg = "Failed to initialize the AuthHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)


####################################################################################################
## Default route
####################################################################################################


@app.route('/', methods = ['GET'])
def home():
    return "This is HuBMAP Web Gateway :)"

####################################################################################################
## Status of API services and File service
####################################################################################################


# JSON version of status
@app.route('/status.json', methods = ['GET'])
def status_json():
    return jsonify(get_status_data())


####################################################################################################
## API Auth
####################################################################################################


@app.route('/cache_clear', methods = ['GET'])
def cache_clear():
    cache.clear()
    logger.info("All gateway API Auth function cache cleared.")
    return "All function cache cleared."


# Auth for private API services
# All endpoints access need to be authenticated
# Direct access will see the JSON message
# Nginx auth_request module won't be able to display the JSON message for 401 response
@app.route('/api_auth', methods = ['GET'])
def api_auth():
    wildcard_delimiter = "<*>"
    # The regular expression pattern takes any alphabetical and numerical characters,
    # % used in URL encoding, and other characters permitted in the URI
    regex_pattern = r"[a-zA-Z0-9_.:%#@!&=+*-]+"

    logger.info("======api_auth request.headers======")
    logger.info(request.headers)

    # Nginx auth_request only cares about the response status code
    # it ignores the response body
    # We use body here only for direct visit to this endpoint
    response_200 = make_response(jsonify({"message": "OK: Authorized"}), 200)
    response_401 = make_response(jsonify({"message": "ERROR: Unauthorized"}), 401)

    # In the json, we use authority as the key to differ each service section
    authority = None
    method = None
    endpoint = None

    # URI = scheme:[//authority]path[?query][#fragment] where authority = [userinfo@]host[:port]
    # This "Host" header is nginx `$http_host` which contains port number,
    # unlike `$host` which doesn't include port number
    # Here we don't parse the "X-Forwarded-Proto" header because the scheme is either HTTP or HTTPS
    if ("X-Original-Request-Method" in request.headers) and ("Host" in request.headers) and ("X-Original-URI" in request.headers):
        authority = request.headers.get("Host")
        method = request.headers.get("X-Original-Request-Method")
        endpoint = request.headers.get("X-Original-URI")

    # method and endpoint are always not None as long as authority is not None
    if authority is not None:
        # Load endpoints from json
        data = load_file(app.config['API_ENDPOINTS_FILE'])

        if authority in data.keys():
            # First pass, loop through the list to find exact static match
            for item in data[authority]:
                if (item['method'].upper() == method.upper()) and (wildcard_delimiter not in item['endpoint']):
                    # Ignore the query string
                    target_endpoint = endpoint.split("?")[0]
                    # Remove trailing slash for comparison
                    if item['endpoint'].strip('/') == target_endpoint.strip('/'):
                        if api_access_allowed(item, request):
                            return response_200
                        else:
                            return response_401

            # Second pass, loop through the list to do the wildcard match
            for item in data[authority]:
                if (item['method'].upper() == method.upper()) and (wildcard_delimiter in item['endpoint']):
                    # First replace all occurrences of the wildcard delimiters with regular expression
                    endpoint_pattern = item['endpoint'].replace(wildcard_delimiter, regex_pattern)
                    # Ignore the query string
                    target_endpoint = endpoint.split("?")[0]
                    # If the full url path matches the regular expression pattern, 
                    # return a corresponding match object, otherwise return None
                    target_endpoint = endpoint.split("?")[0]
                    # Remove trailing slash for comparison
                    if re.fullmatch(endpoint_pattern.strip('/'), target_endpoint.strip('/')) is not None:
                        if api_access_allowed(item, request):
                            return response_200
                        else:
                            return response_401

            # After two passes and still no match found
            # It could be either unknown request method or unknown path
            return response_401

        # Handle the cases when authority not in data.keys() 
        return response_401
    else:
        # Missing lookup_key
        return response_401


####################################################################################################
## File Auth
####################################################################################################

# Auth for assets file service
# URL pattern: https://assets.hubmapconsortium.org/<uuid>/<relative-file-path>[?token=<globus-token>]
# The <uuid> could be one of the following:
# - the actual dataset entity uuid
# - the file uuid (Dataset: thumbnail image or Donor/Sample: metadata/image file)
# - the AVR file uuid (handling of the AVR entity uuid is via uuid-api only)
# The query string with token is optional, but will be used by the portal-ui
# No token is required for accessing AVR files
@app.route('/file_auth', methods = ['GET'])
def file_auth():
    logger.info("======file_auth Original request.headers======")
    logger.info(request.headers)

    # Nginx auth_request only cares about the response status code
    # it ignores the response body
    # We use body here only for description purposes and direct visit to this endpoint
    response_200 = make_response(jsonify({"message": "OK: Authorized"}), 200)
    response_401 = make_response(jsonify({"message": "ERROR: Unauthorized"}), 401)
    response_403 = make_response(jsonify({"message": "ERROR: Forbidden"}), 403)
    response_500 = make_response(jsonify({"message": "ERROR: Internal Server Error"}), 500)

    # Note: 400 and 404 are not supported http://nginx.org/en/docs/http/ngx_http_auth_request_module.html
    # Any response code other than 200/401/403 returned by the subrequest is considered an error 500
    # The end user or client will never see 404 but 500
    response_400 = make_response(jsonify({"message": "ERROR: Bad Request"}), 400)
    response_404 = make_response(jsonify({"message": "ERROR: Not Found"}), 404)

    method = None
    orig_uri = None

    # URI = scheme:[//authority]path[?query][#fragment] where authority = [userinfo@]host[:port]
    # This "Host" header is nginx `$http_host` which contains port number,
    # unlike `$host` which doesn't include port number
    # Here we don't parse the "X-Forwarded-Proto" header because the scheme is either HTTP or HTTPS
    if ("X-Original-Request-Method" in request.headers) and ("X-Original-URI" in request.headers):
        method = request.headers.get("X-Original-Request-Method")
        orig_uri = request.headers.get("X-Original-URI")

    # File access only via http GET
    if method is not None:
        # Supports both GET and HEAD request methods
        if method.upper() in ['GET', 'HEAD']:
            if orig_uri is not None:
                parsed_uri = urlparse(orig_uri)

                logger.debug("======parsed_uri======")
                logger.debug(parsed_uri)

                # Remove the leading slash before split
                path_list = parsed_uri.path.strip("/").split("/")

                # This parsed uuid could either be the entity uuid or a file uuid
                uuid = path_list[0]

                # Also get the "token" parameter from query string
                # query is a dict, keys are the unique query variable names
                # and the values are lists of values for each name
                token_from_query = None
                query = parse_qs(parsed_uri.query)

                if 'token' in query:
                    token_from_query = query['token'][0]

                logger.debug("======token_from_query======")
                logger.debug(token_from_query)

                # Check if the globus token is valid for accessing this secured file
                code = get_file_access(uuid, token_from_query, request)

                logger.debug("======get_file_access() resulting code======")
                logger.debug(code)

                if code == 200:
                    return response_200
                # Returned 400 will be considered as 500 by nginx auth_request module
                elif code == 400:
                    return response_400
                elif code == 401:
                    return response_401
                elif code == 403:
                    return response_403
                # Returned 404 will be considered as 500 by nginx auth_request module
                elif code == 404:
                    logger.warning("The end user or client will never see 404 but 500")
                    return response_404
                elif code == 500:
                    return response_500
            else:
                # Missing dataset UUID in path
                return response_401
        else:
            # Wrong http method
            return response_401
    # Not a valid http request
    return response_401


@app.route('/umls_auth', methods = ['GET'])
def umls_auth():
    logger.info("======umls_auth Original request.headers======")
    logger.info(request.headers)

    # Nginx auth_request only cares about the response status code
    # it ignores the response body
    # We use body here only for description purposes and direct visit to this endpoint
    response_200 = make_response(jsonify({"message": "OK: Authorized"}), 200)
    response_401 = make_response(jsonify({"message": "ERROR: Unauthorized"}), 401)
    response_403 = make_response(jsonify({"message": "ERROR: Forbidden"}), 403)
    response_500 = make_response(jsonify({"message": "ERROR: Internal Server Error"}), 500)

    orig_uri = None

    if "X-Original-URI" in request.headers:
        orig_uri = request.headers.get("X-Original-URI")


    parsed_uri = urlparse(orig_uri)

    logger.debug("======parsed_uri======")
    logger.debug(parsed_uri)

    query = parse_qs(parsed_uri.query)

    if 'umls-key' not in query:
        return response_401
    is_authorized = validate_umls_key(query['umls-key'][0])
    if not is_authorized:
        return response_403
    return response_200


####################################################################################################
## Internal Functions Used By API Auth and File Auth
####################################################################################################

@cached(cache)
def load_file(file):
    with open(file, "r") as f:
        data = json.load(f)
        return data

# Cache the request response for the given URL with using function cache (memoization)
@cached(cache)
def make_api_request_get(target_url):
    now = time.ctime(int(time.time()))

    # Log the first non-cache call, the subsequent requests will juse use the function cache unless it's expired
    logger.info(f'Making a fresh non-cache HTTP request to GET {target_url} at time {now}')

    # Use modified version of globus app secret from configuration as the internal token
    request_headers = create_request_headers_for_auth(auth_helper_instance.getProcessSecret())

    # Disable ssl certificate verification
    response = requests.get(url = target_url, headers = request_headers, verify = False)

    return response

# Make a call to the given target status URL
# We don't want to cache the status request
def status_request(target_url):
    # Disable ssl certificate verification
    response = requests.get(url = target_url, verify = False) 

    return response


# Dict of API status data
def get_status_data():
    # Some constants
    GATEWAY = 'gateway'
    VERSION = 'version'
    BUILD = 'build'
    UUID_API = 'uuid_api'
    ENTITY_API = 'entity_api'
    INGEST_API = 'ingest_api'
    SEARCH_API = 'search_api'
    FILE_ASSETS = 'file_assets'
    CELLS_API = 'cells_api'
    WORKSPACES_API = 'workspaces_api'
    ONTOLOGY_API = 'ontology_api'
    UKV_API = 'ukv_api'
    DATA_PRODUCTS_API = 'data_products_api'
    SCFIND_API = 'scfind_api'
    SPATIALQUERY_API = 'spatialquery_api'

    MYSQL_CONNECTION = 'mysql_connection'
    NEO4J_CONNECTION = 'neo4j_connection'
    ELASTICSEARCH_CONNECTION = 'elasticsearch_connection'
    ELASTICSEARCH_STATUS = 'elasticsearch_status'
    FILE_ASSETS_STATUS = 'file_assets_status'
    SCFIND_STATUS = 'scfind_status'
    SPATIALQUERY_STATUS = 'spatialquery_status'
    BRANCH = 'branch'
    COMMIT = 'commit'
    POSTGRES_CONNECTION = 'postgres_connection'

    # Gateway version and build are parsed from VERSION and BUILD files directly
    # instead of making API calls. So they alwasy present
    status_data = {
        GATEWAY: {
            # Use strip() to remove leading and trailing spaces, newlines, and tabs
            VERSION: (Path(__file__).absolute().parent.parent / 'VERSION').read_text().strip(),
            BUILD: (Path(__file__).absolute().parent.parent / 'BUILD').read_text().strip()
        },
        UUID_API: {},
        ENTITY_API: {},
        INGEST_API: {},
        SEARCH_API: {},
        FILE_ASSETS: {},
        CELLS_API: {},
        WORKSPACES_API: {},
        ONTOLOGY_API: {},
        UKV_API: {},
        DATA_PRODUCTS_API: {},
        SCFIND_API: {},
        SPATIALQUERY_API: {}
    }

    # uuid-api
    uuid_api_response = status_request(app.config['UUID_API_STATUS_URL'])
    if uuid_api_response.status_code == 200:
        # Then parse the response json to determine if neo4j connection is working
        response_json = uuid_api_response.json()
        if VERSION in response_json:
            # Set version
            status_data[UUID_API][VERSION] = response_json[VERSION]

        if BUILD in response_json:
            # Set build
            status_data[UUID_API][BUILD] = response_json[BUILD]

        if MYSQL_CONNECTION in response_json:
            # Add the mysql connection status
            status_data[UUID_API][MYSQL_CONNECTION] = response_json[MYSQL_CONNECTION]

    # entity-api
    entity_api_response = status_request(app.config['ENTITY_API_STATUS_URL'])
    if entity_api_response.status_code == 200:
        # Then parse the response json to determine if neo4j connection is working
        response_json = entity_api_response.json()
        if VERSION in response_json:
            # Set version
            status_data[ENTITY_API][VERSION] = response_json[VERSION]

        if BUILD in response_json:
            # Set build
            status_data[ENTITY_API][BUILD] = response_json[BUILD]

        if NEO4J_CONNECTION in response_json:
            # Add the neo4j connection status
            status_data[ENTITY_API][NEO4J_CONNECTION] = response_json[NEO4J_CONNECTION]

    # ingest-api
    ingest_api_response = status_request(app.config['INGEST_API_STATUS_URL'])
    if ingest_api_response.status_code == 200:
        # Then parse the response json to determine if neo4j connection is working
        response_json = ingest_api_response.json()
        if VERSION in response_json:
            # Set version
            status_data[INGEST_API][VERSION] = response_json[VERSION]

        if BUILD in response_json:
            # Set build
            status_data[INGEST_API][BUILD] = response_json[BUILD]

        if NEO4J_CONNECTION in response_json:
            # Add the neo4j connection status
            status_data[INGEST_API][NEO4J_CONNECTION] = response_json[NEO4J_CONNECTION]

    # search-api
    search_api_response = status_request(app.config['SEARCH_API_STATUS_URL'])
    if search_api_response.status_code == 200:
        # Then parse the response json to determine if elasticsearch cluster is connected
        response_json = search_api_response.json()
        if VERSION in response_json:
            # Set version
            status_data[SEARCH_API][VERSION] = response_json[VERSION]

        if BUILD in response_json:
            # Set build
            status_data[SEARCH_API][BUILD] = response_json[BUILD]

        if ELASTICSEARCH_CONNECTION in response_json:
            # Add the elasticsearch connection status
            status_data[SEARCH_API][ELASTICSEARCH_CONNECTION] = response_json[ELASTICSEARCH_CONNECTION]

        # Also check if the health status of elasticsearch cluster is available
        if ELASTICSEARCH_STATUS in response_json:
            # Add the elasticsearch cluster health status
            status_data[SEARCH_API][ELASTICSEARCH_STATUS] = response_json[ELASTICSEARCH_STATUS]

    # file assets, no need to send headers
    file_assets_response = status_request(app.config['FILE_ASSETS_STATUS_URL'])
    if file_assets_response.status_code == 200:
        # Then parse the response json to determine if neo4j connection is working
        response_json = file_assets_response.json()
        if FILE_ASSETS_STATUS in response_json:
            # Add the file assets status since file is accessible via nginx
            status_data[FILE_ASSETS][FILE_ASSETS_STATUS] = response_json[FILE_ASSETS_STATUS]

    # cells api
    cells_api_response = status_request(app.config['CELLS_API_STATUS_URL'])
    if cells_api_response.status_code == 200:
        response_json = cells_api_response.json()
        if BRANCH in response_json:
            # Set branch
            status_data[CELLS_API][BRANCH] = response_json[BRANCH]

        if COMMIT in response_json:
            # Set commit
            status_data[CELLS_API][COMMIT] = response_json[COMMIT]

        if VERSION in response_json:
            # Set version
            status_data[CELLS_API][VERSION] = response_json[VERSION]

        if POSTGRES_CONNECTION in response_json:
            # Set Postgres connection
            status_data[CELLS_API][POSTGRES_CONNECTION] = response_json[POSTGRES_CONNECTION]

    # workspaces REST api
    workspaces_api_response = status_request(app.config['WORKSPACES_API_STATUS_URL'])
    if workspaces_api_response.status_code == 200:
        response_json = workspaces_api_response.json()
        if VERSION in response_json:
            # Set version
            status_data[WORKSPACES_API][VERSION] = response_json[VERSION]

        if BUILD in response_json:
            # Set build
            status_data[WORKSPACES_API][BUILD] = response_json[BUILD]

    # ontology API
    ontology_api_response = status_request(app.config["ONTOLOGY_API_STATUS_URL"])
    if ontology_api_response.status_code == 200:
        response_json = ontology_api_response.json()
        if VERSION in response_json:
            # Set version
            status_data[ONTOLOGY_API][VERSION] = response_json[VERSION]
        if BUILD in response_json:
            # Set build
            status_data[ONTOLOGY_API][BUILD] = response_json[BUILD]
        if NEO4J_CONNECTION in response_json:
            # Set Neo4j connection
            status_data[ONTOLOGY_API][NEO4J_CONNECTION] = response_json[NEO4J_CONNECTION]

    # ukv API
    ukv_api_response = status_request(app.config["UKV_API_STATUS_URL"])
    if ukv_api_response.status_code == 200:
        response_json = ukv_api_response.json()
        if VERSION in response_json:
            # Set version
            status_data[UKV_API][VERSION] = response_json[VERSION]
        if BUILD in response_json:
            # Set build
            status_data[UKV_API][BUILD] = response_json[BUILD]
        if MYSQL_CONNECTION in response_json:
            # Add the mysql connection status
            status_data[UKV_API][MYSQL_CONNECTION] = response_json[MYSQL_CONNECTION]

    # data products API
    data_products_api_response = status_request(app.config["DATA_PRODUCTS_API_STATUS_URL"])
    if data_products_api_response.status_code == 200:
        response_json = data_products_api_response.json()
        if VERSION in response_json:
            # Set version
            status_data[DATA_PRODUCTS_API][VERSION] = response_json[VERSION]
        if BUILD in response_json:
            # Set build
            status_data[DATA_PRODUCTS_API][BUILD] = response_json[BUILD]
        if MYSQL_CONNECTION in response_json:
            # Add the mysql connection status
            status_data[DATA_PRODUCTS_API][MYSQL_CONNECTION] = response_json[MYSQL_CONNECTION]

    # ScFind API
    scfind_api_response = status_request(app.config["SCFIND_API_STATUS_URL"])
    if scfind_api_response.status_code == 200:
        status_data[SCFIND_API][SCFIND_STATUS] = True
    else:
        status_data[SCFIND_API][SCFIND_STATUS] = False

    # SpatialQuery API
    spatialquery_api_response = status_request(app.config["SPATIALQUERY_API_STATUS_URL"])
    if spatialquery_api_response.status_code == 200:
        status_data[SPATIALQUERY_API][SPATIALQUERY_STATUS] = True
    else:
        status_data[SPATIALQUERY_API][SPATIALQUERY_STATUS] = False
    # Final result
    return status_data


# Get user information dict based on the http request(headers)
# `group_required` is a boolean, when True, 'hmgroupids' is in the output
def get_user_info_for_access_check(request, group_required):
    return auth_helper_instance.getUserInfoUsingRequest(request, group_required)


# Due to Flask's EnvironHeaders is immutable
# We create a new class with the headers property 
# so AuthHelper can access it using the dot notation req.headers
class CustomRequest:
    # Constructor
    def __init__(self, headers):
        self.headers = headers


# Create a dict with HTTP Authorization header with Bearer token
def create_request_headers_for_auth(token):
    auth_header_name = 'Authorization'
    auth_scheme = 'Bearer'

    headers_dict = {
        # Don't forget the space between scheme and the token value
        auth_header_name: auth_scheme + ' ' + token
    }

    return headers_dict


# Check if the target file associated with this uuid is accessible 
# based on token and access level assigned to the entity
# The uuid passed in could either be a real entity (Donor/Sample/Dataset/Publication) uuid or
# a file uuid (Dataset: thumbnail image or Donor/Sample: metadata/image file)
# AVR file uuid is handled via uuid-api only and no token is required
def get_file_access(uuid, token_from_query, request):
    # AVR and AVR files are standalone, not stored in neo4j and won't be available via entity-api
    supported_entity_types = ['Donor', 'Sample', 'Dataset', 'Publication']

    # Returns one of the following codes
    allowed = 200
    bad_request = 400
    authentication_required = 401
    authorization_required = 403
    not_found = 404
    internal_error = 500

    # All lowercase for easy comparison
    ACCESS_LEVEL_PUBLIC = 'public'
    ACCESS_LEVEL_CONSORTIUM = 'consortium'
    ACCESS_LEVEL_PROTECTED = 'protected'
    DATASET_STATUS_PUBLISHED = 'published'

    # Special case used by file assets status only
    if uuid == 'status':
        return allowed

    # request.headers may or may not contain the 'Authorization' header
    final_request = request

    # We'll get the parent entity uuid if the given uuid is indeed a file uuid
    # If the given uuid is actually an entity uuid, just return it
    try:
        entity_uuid, entity_is_avr, given_uuid_is_file_uuid = get_entity_uuid_by_file_uuid(uuid)

        logger.debug(f"The given uuid {uuid} is a file uuid: {given_uuid_is_file_uuid}")

        if given_uuid_is_file_uuid:
            logger.debug(f"The parent entity_uuid: {entity_uuid}")
            logger.debug(f"The entity is AVR: {entity_is_avr}")
    except requests.exceptions.RequestException:
        # We'll just handle 400 and all other cases all together here as 500
        # because nginx auth_request only handles 200/401/403/500
        return internal_error

    # By now, the given uuid is either a real entity uuid
    # or we found the associated parent entity uuid of the given file uuid
    # If the given uuid is an AVR entity uuid (should not happen in normal situation), 
    # it'll go through but 404 returned by the assets nginx 
    # since we don't have any files for this AVR entity
    # If an AVR file uuid, we'll allow the access too and send back the file content
    # No token ever required regardless the given uuid is an AVR entity uuid or AVR file uuid
    if entity_is_avr:
        return allowed

    # For non-AVR entities:
    # Next to determine the data access level of the given uuid by 
    # making a call to entity-api to retrieve the entity first
    entity_api_full_url = app.config['ENTITY_API_URL'] + '/entities/' + entity_uuid

    # Function cache to improve performance
    # Possible response status codes: 200, 401, and 500 to be handled below
    response = make_api_request_get(entity_api_full_url)

    # Using the globus app secret as internal token should always return 200 supposedly
    # If not, either technical issue 500 or something wrong with this internal token 401
    if response.status_code == 200:
        entity_dict = response.json()

        # Won't happen in normal situations, but nice to check
        if 'entity_type' not in entity_dict:
            logger.error(f"Missing 'entity_type' from returned result of entity uuid {entity_uuid}")
            return internal_error

        entity_type = entity_dict['entity_type']

        # The assets service only supports:
        # - Data files contained within a Dataset
        # - Thumbnail file (metadata) for Dataset 
        # - Image and metadata files (metadata) for Sample
        # - Image files (metadata) for Donor
        # - Standalone AVR files (PDF or word doc)
        if entity_type not in supported_entity_types:
            logger.error(f"Unsupported 'entity_type' {entity_type} from returned result of entity uuid {entity_uuid}")
            return bad_request

        # Won't happen in normal situations, but nice to check
        if 'data_access_level' not in entity_dict:
            logger.error(f"Missing 'data_access_level' from returned result of entity uuid {entity_uuid}")
            return internal_error

        # Default
        data_access_level = entity_dict['data_access_level']

        logger.debug(f"======data_access_level returned by entity-api for {entity_type} uuid {entity_uuid}======")
        logger.debug(data_access_level)

        # Donor and Sample `data_access_level` value can only be either "public" or "consortium"
        # Dataset has the "protected" data_access_level due to PHI `contains_human_genetic_sequences`
        # Use `status` to determine the access of Dataset attached thumbnail file (considered as metadata)
        # But the data files contained within the dataset is determined by `data_access_level`
        # A dataset with `status` "Published" (thumbnail file is public accessible) can have 
        # "protected" `data_access_level` (data files within the dataset are protected)
        if (entity_type in ['Dataset', 'Publication']) and given_uuid_is_file_uuid and (entity_dict['status'].lower() == DATASET_STATUS_PUBLISHED):
            # Overwrite the default value
            data_access_level = ACCESS_LEVEL_PUBLIC

            logger.debug(f"======determined data_access_level for dataset attached thumbnail file uuid {uuid}======")
            logger.debug(data_access_level)

        # Throw error 500 if invalid access level value assigned to the dataset
        if data_access_level not in [ACCESS_LEVEL_PUBLIC, ACCESS_LEVEL_CONSORTIUM, ACCESS_LEVEL_PROTECTED]:
            logger.error("The 'data_access_level' value of this dataset " + entity_uuid + " is invalid")
            return internal_error

        # Get the user access level based on token (optional) from HTTP header or query string
        # The globus token can be specified in the 'Authorization' header OR through a "token" query string in the URL
        # Use the globus token from URL query string if present and set as the value of 'Authorization' header
        # If not found, default to the 'Authorization' header
        # Because auth_helper_instance.getUserDataAccessLevel() checks against the 'Authorization' header
        if token_from_query is not None:
            # NOTE: request.headers is type 'EnvironHeaders', 
            # and it's immutable(read only version of the headers from a WSGI environment)
            # So we can't modify the request.headers
            # Instead, we use a custom request object and set as the 'Authorization' header 
            logger.debug("======set Authorization header with query string token value======")

            custom_headers_dict = create_request_headers_for_auth(token_from_query)

            # Overwrite the default final_request
            # CustomRequest and Flask's request are different types,
            # but the Commons's AuthHelper only access the request.headers
            # So as long as headers from CustomRequest instance can be accessed with the dot notation
            final_request = CustomRequest(custom_headers_dict)

        # By now, request.headers may or may not contain the 'Authorization' header
        logger.debug("======file_auth final_request.headers======")
        logger.debug(final_request.headers)

        # When Authorization is not present, return value is based on the data_access_level of the given dataset
        # In this case we can't call auth_helper_instance.getUserDataAccessLevel() because it returns HTTPException
        # when Authorization header is missing
        if 'Authorization' not in final_request.headers:
            # Return 401 if the data access level is consortium or protected since
            # they require token but Authorization header missing
            if data_access_level != ACCESS_LEVEL_PUBLIC:
                return authentication_required
            # Only return 200 since public dataset doesn't require token
            return allowed

        # By now the Authorization is present and it's either provided directly from the request headers or
        # query string (overwriting)
        # Then we can call auth_helper_instance.getUserDataAccessLevel() to find out the user's assigned access level
        try:
            # The user_info contains HIGHEST access level of the user based on the token
            # Default to ACCESS_LEVEL_PUBLIC if none of the Authorization/Mauthorization header presents
            # This call raises an HTTPException with a 401 if any auth issues are found
            user_info = auth_helper_instance.getUserDataAccessLevel(final_request)

            logger.info("======user_info======")
            logger.info(user_info)
        # If returns HTTPException with a 401, invalid header format or expired/invalid token
        except HTTPException as e:
            msg = "HTTPException from calling auth_helper_instance.getUserDataAccessLevel() HTTP code: " + str(e.get_status_code()) + " " + e.get_description() 

            logger.warning(msg)

            # In the case of requested dataset is public but provided globus token is invalid/expired,
            # we'll return 401 so the end user knows something wrong with the token rather than allowing file access
            return authentication_required

        # By now the user_info is returned and based on the logic of auth_helper_instance.getUserDataAccessLevel(), 
        # 'data_access_level' should always be found user_info and its value is always one of the 
        # ACCESS_LEVEL_PUBLIC, ACCESS_LEVEL_CONSORTIUM, or ACCESS_LEVEL_PROTECTED
        # So no need to check unknown value
        user_access_level = user_info['data_access_level'].lower()

        # By now we have both data_access_level and the user_access_level obtained with one of the valid values
        # Allow file access as long as data_access_level is public, no need to care about the
        # user_access_level (since Authorization header presents with valid token)
        if data_access_level == ACCESS_LEVEL_PUBLIC:
            return allowed

        # When data_access_level is consortium, allow access only when the user_access_level
        # (remember this is the highest level) is consortium or protected
        if (data_access_level == ACCESS_LEVEL_CONSORTIUM and
            (user_access_level == ACCESS_LEVEL_PROTECTED or user_access_level == ACCESS_LEVEL_CONSORTIUM)):
            return allowed

        # When data_access_level is protected, allow access only when user_access_level is also protected
        if data_access_level == ACCESS_LEVEL_PROTECTED and user_access_level == ACCESS_LEVEL_PROTECTED:
            return allowed

        # All other cases
        return authorization_required
    # Something wrong with fulfilling the request with secret as token
    # E.g., for some reason the gateway returns 401
    elif response.status_code == 401:
        logger.error(f"Couldn't authenticate the request made to {entity_api_full_url} with internal token")
        return authorization_required
    elif response.status_code == 404:
        logger.error(f"Unable to find uuid {entity_uuid}")
        return not_found
    # All other cases with 500 response
    else:
        logger.error(f"Failed to get the access level of entity with uuid {entity_uuid}")
        return internal_error


def validate_umls_key(umls_key):
    validator_key = app.config['UMLS_KEY']
    base_url = app.config['UMLS_VALIDATE_URL']
    url = base_url + '?validatorApiKey=' + validator_key + '&apiKey=' + umls_key
    result = requests.get(url=url)
    if result.json() == True:
        return True
    else:
        return False


# Always pass through the requests with using modified version of the globus app secret as internal token
def is_secrect_token(request):
    internal_token = auth_helper_instance.getProcessSecret()
    parsed_token = None

    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        parsed_token = auth_header[6:].strip()

    if internal_token == parsed_token:
        return True

    return False


# Check if access to the given endpoint item is allowed
# Also check if the globus token associated user is a member of the specified group associated with the endpoint item
def api_access_allowed(item, request):
    logger.info("======Matched endpoint======")
    logger.info(item)

    # Check if auth is required for this endpoint
    if item['auth'] == False:
        return True

    # Check if using modified version of the globus app secret as internal token
    if is_secrect_token(request):
        return True

    # When auth is required, we need to check if group access is also required
    group_required = True if 'groups' in item else False

    # Get user info and do further parsing
    user_info = get_user_info_for_access_check(request, group_required)
    
    logger.info("======user_info======")
    logger.info(user_info)

    # If returns error response, invalid header or token
    if isinstance(user_info, Response):
        return False

    # Otherwise, user_info is a dict and we check if the group ID of target endpoint can be found
    # in user_info['hmgroupids'] list
    # Key 'hmgroupids' presents only when group_required is True
    if group_required:
        for group in user_info['hmgroupids']:
            if group in item['groups']:
                return True

        # None of the assigned groups match the group ID specified in item['groups']
        return False

    # When no group access required and user_info dict gets returned
    return True


# If the given uuid is a file uuid, get the parent entity uuid
# If the given uuid itself is an entity uuid, just return it
# The bool entity_is_avr is returned as a flag
# The bool given_uuid_is_file_uuid is returned as a flag
def get_entity_uuid_by_file_uuid(uuid):
    entity_uuid = None
    # Assume the target entity is NOT AVR record by default
    entity_is_avr = False
    # Assume the given uuid is a file uuid by default
    # First determine if the given uuid is whether an entity uuid or a file uuid
    # All file uuids start with ffff
    # TODO: add a new endpoint in uuid-api for this file id check instead of hardcoding
    given_uuid_is_file_uuid = uuid.startswith("ffff")

    # Make a call to the uuid-api's /file-id endpoint to get `ancestor_uuid`
    if given_uuid_is_file_uuid:
        uuid_api_file_url = f"{app.config['UUID_API_URL']}/file-id/{uuid}"

        # Function cache to improve performance
        response = make_api_request_get(uuid_api_file_url)

        # 200: this given uuid is indeed a valid file uuid
        # 400: invalid file uuid format
        # 404: this given uuid does not exist in the files table
        if response.status_code == 200:
            file_uuid_dict = response.json()

            if 'ancestor_uuid' in file_uuid_dict:
                logger.debug(f"======The given uuid {uuid} is a file uuid======")

                # For file uuid, its ancestor_uuid (the parent_id when generating this file uuid)
                # is the actual entity uuid that can be used to get back the data_access_level
                # Overwrite the default value
                entity_uuid = file_uuid_dict['ancestor_uuid']
            else:
                logger.error(f"Missing 'ancestor_uuid' from resulting json for the given file_uuid {uuid}")

                raise requests.exceptions.RequestException(response.text)
        elif response.status_code == 404:
            # It could be a regular entity uuid but will return 404 by /file-id/<uuid>
            # We just log this and move forward
            # The call to entity-api will tell us if this dataset uuid exists and valid
            logger.debug(f"======Unable to find the file uuid: {uuid}, consider it as an entity uuid======")

            # Treat the given uuid as an entity uuid
            entity_uuid = uuid

            # Overwrite the default value
            given_uuid_is_file_uuid = False
        else:
            # uuid-api returns 400 if the given id is invalid
            msg = f"Invalid file uuid sent to uuid-api: {uuid}"
            # Log the full stack trace, prepend a line with our message
            logger.exception(msg)

            logger.debug("======status code from uuid-api======")
            logger.debug(response.status_code)

            logger.debug("======response text from uuid-api======")
            logger.debug(response.text)

            # Also bubble up the error message from uuid-api
            raise requests.exceptions.RequestException(response.text)
    else:
        # Treat the given uuid as an entity uuid
        entity_uuid = uuid

    # Further check the entity type registered with uuid-api to determine if it's AVR or not
    uuid_api_entity_url = f"{app.config['UUID_API_URL']}/hmuuid/{entity_uuid}"

    # Function cache to improve performance
    response = make_api_request_get(uuid_api_entity_url)

    if response.status_code == 200:
        entity_uuid_dict = response.json()

        if 'type' in entity_uuid_dict:
            if entity_uuid_dict['type'].upper() == 'AVR':
                logger.debug(f"======The target entity_uuid {entity_uuid} is an AVR uuid======")

                entity_is_avr = True
        else:
            logger.error(f"Missing 'type' from resulting json for the target entity_uuid {entity_uuid}")

            raise requests.exceptions.RequestException(response.text)
    else:
        msg = f"Unable to make a request to query the target entity uuid via uuid-api: {entity_uuid}"
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)

        logger.debug("======status code from uuid-api======")
        logger.debug(response.status_code)

        logger.debug("======response text from uuid-api======")
        logger.debug(response.text)

        # Also bubble up the error message from uuid-api
        raise requests.exceptions.RequestException(response.text)

    # Return the entity uuid string, if the entity is AVR, and 
    # if the given uuid is a file uuid or not (bool)
    return entity_uuid, entity_is_avr, given_uuid_is_file_uuid


