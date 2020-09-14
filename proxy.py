import sys
import os
import enum
import socket
import _thread
import time
cache = {}


class HttpRequestInfo(object):
    """
    Represents a HTTP request information
    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.
    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.
    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.
    requested_host: the requested website, the remote website
    we want to visit.
    requested_port: port of the webserver we want to visit.
    requested_path: path of the requested resource, without
    including the website name.
    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    # to_http_string DONE
    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:
        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n
        (just join the already existing fields by \r\n)
        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.

        """

        string = self.method + " " + self.requested_path + " HTTP/1.0\r\n"
        for header in self.headers:
            string = string + header[0] + ": " + header[1] + "\r\n"
        string = string + "\r\n"

        return string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above """
        return str(self.code) + " " + self.message

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.
    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.
    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    setup_sockets(proxy_port_number)
    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    return None



def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.
    But feel free to add your own classes/functions.
    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", int(proxy_port_number)))
    s.listen(20)
    while True:
        client_socket, address = s.accept()  # accepts connection from client
        print(f"Connection from {address} has been established!")
        data = ""
        string = ""
        while data != "\r\n":
            data = client_socket.recv(1024).decode("ascii")
            string += data
        if not (string in cache):
         cache[string] = ""
        _thread.start_new_thread(do_socket_logic, (client_socket, address,string))


def do_socket_logic(client_socket,address,string):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    if cache.get(string) == "":
        start_time = time.time()
        http_object = http_request_pipeline(address, string)
        if isinstance(http_object, HttpRequestInfo):
            print("compose http request message")
            string = http_object.to_http_string()
            byte_array = http_object.to_byte_array(string)
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_socket.connect((http_object.requested_host, http_object.requested_port))
            new_socket.send(byte_array)
            s = b""
            while True:
             received = new_socket.recv(1024)
             client_socket.send(received)
             if len(received) < 1024:
                break
        # Now set up connection with requested server, send this byte array to requested server, and wait for response
        else:
            string = http_object.to_http_string()
            byte_array = http_object.to_byte_array(string)
            client_socket.send(byte_array)
            print("Display error message")
        print("time taken : %s seconds" % (time.time() - start_time))
    else:
        start_time = time.time()
        client_socket.send(cache.get(string).to_byte_array)
        print("time taken : %s seconds" % (time.time() - start_time))
    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.
    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo
    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.
    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    validity = check_http_request_validity(http_raw_data)
    # Return error if needed, then:
    if validity == HttpRequestState.NOT_SUPPORTED:
        error = HttpErrorResponse(501, "Not Implemented")
        return error
    elif validity == HttpRequestState.INVALID_INPUT:
        error = HttpErrorResponse(400, "Bad Request")
        return error
    elif validity == HttpRequestState.GOOD:
        parsed = parse_http_request(source_addr,http_raw_data)
        sanitize_http_request(parsed)
        return parsed

    return None


# parse DONE
def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """

    list = http_raw_data.split()
    method = list[0]
    headers = []
    if len(list) > 3:
        s = " "
        list[3] = s.join(list[3:])
        for i in range(len(list) - 4):
            list.pop()
        headers = list[3]
        headers = headers.split()
        j = 0
        headers = [i + j for i, j in zip(headers[::2], headers[1::2])]
        for header in headers:
            headers[headers.index(header)] = header.split(':', 1)
    if len(list) == 4 and "host" in list[3].lower():
        # print("relative path")
        requested_path = list[1]

        if ":" in headers[0][1]:
            requested_host = headers[0][1].split(':')[0]
            requested_port = headers[0][1].split(':')[1]
        else:
            requested_host = headers[0][1]
            requested_port = 80
    else:

        path = list[1]
        if "http" in path.lower():
            path = path.split("://")[1]
        if ":" in path:
            path = path.split(":")
            if "/" in path[1]:
                temp = path[1].split("/")
                requested_port = temp[0]
                requested_path = "/" + temp[1]
            else:
                requested_port = path[1]
                requested_path = "/"
            requested_host = path[0]
        else:
            requested_port = 80
            if "/" in path:
                temp = path.split("/")
                requested_host = temp[0]
                requested_path = "/" + temp[1]
            else:
                requested_host = path
                requested_path = "/"

    # print("method = " + method,"requested_host = " + requested_host,"requested_port = " + str(requested_port), "requested_path = " +requested_path,"headers = " + str(headers), sep='\n')
    # Replace this line with the correct values.
    ret = HttpRequestInfo(source_addr, method, requested_host, int(requested_port), requested_path, headers)
    return ret  # DO


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid
    returns:
    One of values in HttpRequestState
    """

    # return HttpRequestState.GOOD (for example)
    lines = http_raw_data.split("\r\n")
    if http_raw_data.endswith("\r\n\r\n"):
        lines.pop()
        lines.pop()
    elif http_raw_data.endswith("\r\n"):
        lines.pop()

    first_line = lines[0].split()
    # print(first_line)

    if len(first_line) == 3:
        for element in first_line:
            if element == '':
                return HttpRequestState.INVALID_INPUT
        # HERE I HAVE 3 NON-EMPTY COMPONENTS
        if not (first_line[2].lower().startswith("http/")):
            return HttpRequestState.INVALID_INPUT

    else:
        return HttpRequestState.INVALID_INPUT
    # here request has 3 non-empty components, http version is valid
    if first_line[1].startswith('/'):
        # relative path
        if len(lines) < 2:
            return HttpRequestState.INVALID_INPUT
        elif not (lines[1].lower().startswith("host")):
            return HttpRequestState.INVALID_INPUT

    if len(lines) > 1:
        # fy headers
        headers = lines[1:]

        for header in headers:
            if not (":" in header):
                return HttpRequestState.INVALID_INPUT
            elif len(header.split(":", 2)) != 2 or header.split(":", 2)[0] == '' or header.split(":", 2)[1] == '':
                return HttpRequestState.INVALID_INPUT

    if first_line[0].lower() in ['get', 'head', 'post', 'put']:
        # print("the method is valid but npt necessarily supported")
        if first_line[0].lower() != "get":
        
            return HttpRequestState.NOT_SUPPORTED
    else:
        return HttpRequestState.INVALID_INPUT
    # here request has 3 non-empty components, http version is valid and method is valid and supported

    return HttpRequestState.GOOD


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.
    for example, expand a full URL to relative path + Host header.
    returns:
    nothing, but modifies the input object
    """
    print("*" * 50)
    print("[sanitize_http_request] Implement me!")
    print("*" * 50)
    if len(request_info.headers) > 0 and request_info.headers[0][0].lower() != "host":
        request_info.headers.insert(0, ["Host", request_info.requested_host + ":" + str(request_info.requested_port)])


# print("---------Request after sanitization------")
# print("method = " + request_info.method, "requested_host = " + request_info.requested_host, "requested_port = " + str(request_info.requested_port), "requested_path = " +request_info.requested_path, "headers = " + str(request_info.headers), sep='\n')


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*
    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.
    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)
    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)



if __name__ == "__main__":
    main()
