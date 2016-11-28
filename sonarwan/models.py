import csv
import random
from constants import Transport


def merge_dicts(base, to_merge, operation):
    """ Merge to_merge dict in base dict applying and operation when keys are the same"""

    for k, v in to_merge.items():
        if k in base:
            base[k] = operation(base[k], v)
        else:
            base[k] = v


def unmerge_dicts(base, to_unmerge, operation):
    """ Unmerge to_unmerge dict from base dicts by applying an operation on values when key is the same"""

    for k, v in to_unmerge.items():
        if k in base:
            base[k] = operation(base[k], v)


def similarity(base, k, v):
    if k in base:
        compare_value = base[k]
        length = min(len(compare_value), len(v))
        count = 0

        for i in range(length):
            if (not compare_value[i].isalnum() and not v[i].isalnum()
                ) or compare_value[i].upper() == v[i].upper():
                count += 1
            else:
                return -1
        return count / max(len(compare_value), len(v))
    return 0


class ActivityDataManager(object):
    """Contains only utils classes to manage activity"""

    def add_activity(self, time, bytes_count):
        time_string = time.replace(microsecond=0).isoformat()
        self.activity[time_string] = self.activity.get(time_string,
                                                       0) + int(bytes_count)

    def merge_activity(self, other_activity):
        def sum_fn(v1, v2):
            return v1 + v2

        merge_dicts(self.activity, other_activity, sum_fn)


class App(object):
    """An App is a container of services. An App corresponds to one device.
    
    It has characteristics for the similarity logic to be applied

    An App can be a Web Browser, a mobile App, etc.
    """

    def __init__(self):

        self.characteristics = {}
        self.services = []

        # Maps every stream to a service to have fast access
        self.stream_to_service = {}

    def update_app(self, app_args):
        """Add new characteristics and updates them if new characteristic is longer than current"""

        for k in app_args:
            current_value = self.characteristics.get(k)
            new_value = app_args.get(k)

            if (not current_value) or (new_value and
                                       len(new_value) > len(current_value)):
                self.characteristics[k] = new_value

    def process_service_from_new_stream(self, service, time, length,
                                         stream_number):
        """It can create a new service or find an existing one that matches.
        It links the stream to the service

        If new Service is created, it is added to App services
        """
        existing = False
        curr_service = service

        for each in self.services:
            if each.name == service.name:
                existing = True
                curr_service = each
                break

        if not existing:
            self.services.append(curr_service)

        curr_service.add_activity(time, length)
        self.stream_to_service[stream_number] = curr_service

        return curr_service


class Service(ActivityDataManager):
    """A Service represents a consumption of a Web Service
    
    It can be detected by different methods:
        - Url Service: it detects the name of the service based on the url.
          For example: www.infobae.com will be 'infobae' service.
          This url can be obtained from the header host of HTTP requests or
          because of DNS request with some IP as answer and then consuming that IP.
          This services have a 'Generic' type.

        - DB Service: it is detected by the dataset, because of the url its consuming or
          the IP. This services have a specific type.
    
    A Service will be:
        - Auhorless Service: if the App that triggered it was not detected
        - App Consumed Service: if the App that consumed it was detected (also the device is detected)
        
    Services are the same if they have same name
    """

    def __init__(self):
        self.activity = {}
        self.name = None
        self.type = None
        self.ips = set()
        self.hosts = set()

    @classmethod
    def from_characteristics(cls, characteristics):
        service = cls()
        service.name = characteristics.get('name') or 'Unknown'
        service.type = characteristics.get('type') or 'Unknown'
        return service

    @classmethod
    def from_service(cls, p_service):
        service = cls()
        service.name = p_service.name
        service.type = p_service.type
        service.activity = p_service.activity
        service.ips = p_service.ips
        service.hosts = p_service.hosts
        return service

    @classmethod
    def from_name(cls, name):
        service = cls()
        service.name = name
        service.type = 'Generic'
        return service

    @classmethod
    def from_ip_only(cls, ip):
        service = cls()
        service.name = 'Unknown (IP {})'.format(ip)
        service.type = 'Generic'
        return service


class AuthorlessService(Service):
    """An Authorless Service is a Service that has no App (and no Device) associated
    
    This services are originated because of:
        - Encrypted Traffic: TLS traffic or propietary protocols at TCP level
        - TCP Traffic that is not HTTP
        - UDP packages
        - HTTP traffic with no information about the device
    """

    def __init__(self):
        super().__init__()

        # This services can have multiple streams from different devices
        # that are consuming this service. For example WhatsApp can be 
        # used from different devices in same capture

        self.activity_per_stream = {Transport.UDP: {}, Transport.TCP: {}}

    def add_activity_to_stream(self, protocol, stream, time, bytes_count):
        time_string = time.replace(microsecond=0).isoformat()

        if stream not in self.activity_per_stream[protocol]:
            self.activity_per_stream[protocol][stream] = {}

        self.activity_per_stream[protocol][stream][
            time_string] = self.activity_per_stream[protocol][stream].get(
                time_string, 0) + int(bytes_count)

    def remove_activity_from_stream(self, protocol, stream):
        def substract_fn(v1, v2):
            return v1 - v2

        unmerge_dicts(self.activity,
                      self.activity_per_stream[protocol][stream], substract_fn)
        del self.activity_per_stream[protocol][stream]

    def is_empty(self):
        """Return True if it has no more streams left. 
        This occures when all streams could be assigned to an App (and a Device)
        """

        return self.activity_per_stream[
            Transport.TCP] == {} and self.activity_per_stream[
                Transport.UDP] == {}


class Device(ActivityDataManager):
    """A Device is a node of the network that has one unique IP inside LAN
    
    It is a container of Apps. 
    
    It has extra activity (not only the App's Services activity)
    because it can have activity that does not include Apps or Services, that is,
    originated from the OS itself (for example some HTTP message to 'connectivitycheck.android.com')
    
    For example a smartphone, laptop, desktop computer, smartTV, etc.
    """

    def __init__(self, inference_engine):
        self.apps = []
        self.characteristics = {}
        self.activity = {}

        # List of services that are not associated with App
        self.unasigned_services = []
        self.stream_to_unasigned_service = {}

        # For the app (and later the service) can be obtained with stream number
        self.stream_to_app = {}

        self.inference_engine = inference_engine

    def match_score(self, device_args, app_args):
        """Based on device and app dictionary of characteristics it returns a score of correspondence

        In case it is incompatible (example device is iPad and characteristic has iPhone as model)
        it returns -1
        """

        score = 0

        for k, v in device_args.items():
            sim = similarity(self.characteristics, k, v)
            if sim == -1:
                return -1
            score += sim

        for app in self.apps:
            for k, v in app_args.items():
                sim = similarity(app.characteristics, k, v)
                if sim != -1:
                    score += sim

        return score

    def update(self, device_args, app_args, stream_number):
        """Updates only characteristics of Device and, in some cases, corresponding App"""

        if device_args:
            self.update_device(device_args)

        if app_args:
            app = self.update_apps(app_args)
            self.stream_to_app[stream_number] = app

    def update_apps(self, app_args):
        """Updates an App. This App can be:
        
            - Best matching App
            - New App
        """
        apps = []
        max_score = float('-inf')

        for each_app in self.apps:
            score = 0
            incompatible = False
            for k, v in app_args.items():
                sim = similarity(each_app.characteristics, k, v)
                if sim == -1:
                    incompatible = True
                    break
                else:
                    score += sim
            if not incompatible:
                if score > 0:
                    if score == max_score:
                        apps.append(each_app)
                    elif score > max_score:
                        max_score, apps = score, [each_app]

        app = None
        if apps:
            app = random.choice(apps)
        elif app_args:
            app = App()
            self.apps.append(app)

        app.update_app(app_args)

        return app

    def update_device(self, device_args):
        """Add new characteristics and updates them if new characteristic is longer than current.
        After that, it checks if it can infer new characteristics with the inference_engine
        """

        for k in device_args:
            current_value = self.characteristics.get(k)
            new_value = device_args.get(k)

            if (not current_value) or (new_value and
                                       len(new_value) > len(current_value)):
                self.characteristics[k] = new_value

        inferences = self.inference_engine.analyze_inference(
            self.characteristics)
        if inferences:
            self.characteristics.update(inferences)

    def process_unasigned_service_from_new_stream(self, service, time, length,
                                                   stream_number):
        """It can create a new service or find an existing one that matches.
        It links the stream to the service

        If new Service is created, it is added to unasigned services
        """
        existing = False
        curr_service = service

        for each in self.unasigned_services:
            if each.name == service.name:
                existing = True
                curr_service = each
                break

        if not existing:
            self.unasigned_services.append(curr_service)

        curr_service.add_activity(time, length)
        self.stream_to_unasigned_service[stream_number] = curr_service

        return curr_service

    def get_service_from_stream(self, stream_number):
        """Can return an App Service or an unasigned Service"""
        app = self.stream_to_app.get(stream_number)
        if app:
            return app.stream_to_service.get(stream_number)
        else:
            unasigned_service = self.stream_to_unasigned_service.get(
                stream_number)
            if not unasigned_service:
                return None
            return unasigned_service


class DeviceLess():
    """Used for JSON output"""

    def __init__(self, unassigned_services, apps, characteristics, activity):
        self.apps = apps
        self.unassigned_services = unassigned_services
        self.characteristics = characteristics
        self.activity = activity


class AppLess():
    """Used for JSON output"""

    def __init__(self, characteristics, services):
        self.characteristics = characteristics
        self.services = services


class ServiceLess():
    """Used for JSON output"""

    def __init__(self, activity, name, type_param, ips, hosts):
        self.activity = activity
        self.name = name
        self.type = type_param
        self.ips = list(ips)
        self.hosts = list(hosts)
