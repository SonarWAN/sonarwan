from models import Device, AuthorlessService, Service
from constants import Transport

import random
import streams

import ipaddress


def is_dns_response(pkg):
    return hasattr(pkg.dns, 'a')


def is_request(pkg):
    return hasattr(pkg.http, 'request')


def get_dns_answers(pkg):
    ret = []
    for field_line in pkg.dns._get_all_field_lines():
        if ':' in field_line:
            field_name, field_line = field_line.split(':', 1)
            if (field_name.strip() == 'Address'):
                ret.append(field_line.strip())
    return ret


def is_client_hello(pkg):
    return (hasattr(pkg.ssl, 'record') and
            pkg.ssl.record.split(': ')[-1] == 'Client Hello')


def create_stream_dict(pkg):
    transport_pkg = pkg.udp if hasattr(pkg, 'udp') else pkg.tcp
    return {
        'ip_src': pkg.ip.src,
        'ip_dst': pkg.ip.dst,
        'port_src': transport_pkg.srcport,
        'port_dst': transport_pkg.dstport
    }


def get_cipher_suite(pkg):
    l = pkg.ssl._get_all_fields_with_alternates()
    cipher_suite = [x for x in l if x.name == 'ssl.handshake.ciphersuite']
    return list(map(lambda x: (x.raw_value, x.showname_value), cipher_suite))


def get_significant_name_from_url(url):
    chars = 3
    count = 0
    last_period = len(url)
    for i in range(len(url) - 1, -1, -1):
        if url[i] == '.':
            if count > chars:
                return url[i + 1:last_period]
            else:
                count = 0
                last_period = i
        else:
            count += 1
    if count > chars:
        return url[0:last_period]
    else:
        return url


class Handler(object):
    def __init__(self, environment):
        self.environment = environment

    def search_service(self, pkg):
        service = self.environment.service_analyzer.find_service_from_ip(
            pkg.ip.dst)
        if service:
            service.ips.add(pkg.ip.dst)
            return service
        else:
            host = self.environment.find_host(pkg.ip.dst)
            if host:
                name = get_significant_name_from_url(host)
                ret_service = self.environment.service_analyzer.find_service_from_absolute_url(
                    host
                ) or self.environment.service_analyzer.find_service_from_url(
                    host) or Service.from_name(name)

                ret_service.hosts.add(host)
                return ret_service
            else:
                return None


class DNSHandler(Handler):
    def process(self, pkg):
        if self.needs_processing(pkg):
            answers = get_dns_answers(pkg)
            for each in answers:
                if each not in self.environment.address_host:
                    self.environment.address_host[each] = []
                self.environment.address_host[each].append(pkg.dns.qry_name)

    def needs_processing(self, pkg):
        return is_dns_response(pkg)


class TransportHandler(Handler):
    def process(self, pkg):

        if self.needs_processing(pkg):
            self.process_new_stream(pkg)

        else:
            self.process_existing_stream(pkg)

    def process_existing_stream(self, pkg):
        time, length = pkg.sniff_time, pkg.length

        stream = self.get_stream(pkg)

        if self.environment.has_device_from_stream(pkg):
            device = self.environment.locate_device(pkg)
            device.add_activity(time, length)

            service = device.get_service_from_stream(stream)
            if service:
                service.add_activity(time, length)

        elif self.environment.has_service_from_stream(pkg):
            service = self.environment.locate_service(pkg)
            service.add_activity(time, length)
            service.add_activity_to_stream(self.get_protocol(), stream, time,
                                           length)

        elif self.environment.has_temporal_stream(pkg):
            self.environment.temporal_stream_map[self.get_protocol()][
                stream].append((time, length))

    def process_new_stream(self, pkg):
        service = self.search_service(pkg)

        if service:
            self.process_new_detected_service(service, pkg)
        else:
            self.environment.temporal_stream_map[self.get_protocol()][
                self.get_stream(pkg)] = [(pkg.sniff_time, pkg.length)]

    def process_new_detected_service(self, candidate_service, pkg):
        name = candidate_service.name

        if self.environment.already_exists_authorless_service(name):
            service = self.environment.get_existing_authorless_service(name)
            service.hosts.update(candidate_service.hosts)
            service.ips.update(candidate_service.ips)
        else:
            service = AuthorlessService.from_service(candidate_service)

            # If found service by name and not by IP
            if not ipaddress.ip_address(pkg.ip.dst).is_private:
                service.ips.add(pkg.ip.dst)
            self.environment.authorless_services.append(service)

        time, length = pkg.sniff_time, pkg.length

        stream = self.get_stream(pkg)
        protocol = self.get_protocol()

        service.add_activity(time, length)

        # Add stream to current service
        service.add_activity_to_stream(protocol, stream, time, length)

        self.environment.service_stream_map[protocol][stream] = service

    def needs_processing(self, pkg):
        return not self.environment.previously_analized_stream(pkg)


class UDPHandler(TransportHandler):
    def get_stream(self, pkg):
        return pkg.udp.stream

    def get_protocol(self):
        return Transport.UDP


class TCPHandler(TransportHandler):
    def get_stream(self, pkg):
        return pkg.tcp.stream

    def get_protocol(self):
        return Transport.TCP


class HTTPHandler(Handler):
    def search_service(self, pkg):
        service = super().search_service(pkg)
        # if pkg.http.host == 'i0.wp.com' or pkg.http.host == 'i1.wp.com':
        #     import ipdb; ipdb.set_trace()

        if service:
            return service

        if hasattr(pkg.http, 'host'):
            name = get_significant_name_from_url(pkg.http.host)
            service = Service.from_name(name)
            service.hosts.add(pkg.http.host)
            return service
        else:
            return None

    def process(self, pkg):
        if self.environment.has_device_from_stream(pkg):

            device = self.environment.locate_device(pkg)
            self.process_existing_stream(pkg, device)

        else:
            self.process_new_stream(pkg)

    def process_existing_stream(self, pkg, device):
        def action(device_args, app_args):
            device.update(device_args, app_args, pkg.tcp.stream)

        if hasattr(pkg.http, 'user_agent'):
            user_agent = pkg.http.user_agent
            self.process_user_agent(user_agent, action)

        time, length = pkg.sniff_time, pkg.length
        device.add_activity(time, length)

        service = device.get_service_from_stream(pkg.tcp.stream)
        if service:
            service.add_activity(time, length)

    def merge_temporal_stream(self, device, pkg):
        for each in self.environment.locate_temporal(pkg):
            device.add_activity(each[0], each[1])
            service = device.get_service_from_stream(pkg.tcp.stream)
            if service:
                service.add_activity(each[0], each[1])

        del self.environment.temporal_stream_map[Transport.TCP][pkg.tcp.stream]

    def merge_authorless_service(self, device, pkg):
        existing_service = self.environment.locate_service(pkg)

        activity_from_stream = existing_service.activity_per_stream[
            Transport.TCP][pkg.tcp.stream]

        device.merge_activity(activity_from_stream)
        service = device.get_service_from_stream(pkg.tcp.stream)
        if service:
            service.merge_activity(activity_from_stream)

        # Only remove current stream for service,
        # not the whole service, as it could be consumed
        # by other devices also (think WhatsApp)

        existing_service.remove_activity_from_stream(Transport.TCP,
                                                     pkg.tcp.stream)

        del self.environment.service_stream_map[Transport.TCP][pkg.tcp.stream]

        # Only remove authorless Service
        # if no streams are left associated with it
        if existing_service.is_empty():
            self.environment.authorless_services.remove(existing_service)

    def process_new_stream(self, pkg):
        def action(device_args, app_args):
            device = self.solve_device(device_args, app_args)
            device.update(device_args, app_args, pkg.tcp.stream)

            self.environment.device_stream_map[Transport.TCP][
                pkg.tcp.stream] = device

            device.add_activity(pkg.sniff_time, pkg.length)

            app = device.stream_to_app.get(pkg.tcp.stream)

            if app:
                service = self.search_service(pkg)
                if service:
                    incorporated_service = app.proccess_service_from_new_stream(
                        service, pkg.sniff_time, pkg.length, pkg.tcp.stream)

                    incorporated_service.ips.add(pkg.ip.dst)
                    incorporated_service.hosts.add(pkg.http.host)

            if self.environment.has_temporal_stream(pkg):
                self.merge_temporal_stream(device, pkg)

            if self.environment.has_service_from_stream(pkg):
                self.merge_authorless_service(device, pkg)

        if is_request(pkg) and hasattr(pkg.http, 'user_agent'):
            user_agent = pkg.http.user_agent
            self.process_user_agent(user_agent, action)

    def process_user_agent(self, user_agent, action):

        matchers = self.environment.ua_analyzer.get_best_match(user_agent)

        device_args = matchers.get('device_args')
        app_args = matchers.get('app_args')

        if device_args or app_args:
            action(device_args, app_args)

    def solve_device(self, device_args, app_args):
        devices = []
        max_score = 0
        for d in self.environment.devices:
            score = d.match_score(device_args, app_args)
            if max_score > 0 and score == max_score:
                devices.append(d)
            elif score > max_score:
                max_score, devices = score, [d]

        if devices:
            device = random.choice(devices)
        else:
            device = self.environment.create_device()

        return device
