from models import Device, DeviceLess, AuthorlessService, ServiceLess
from constants import Transport

import random
import streams


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


def get_significant_service_from_url(url, chars):
    count = 0
    for i in range(len(url) - 1, -1, -1):
        if url[i] == '.':
            if count > chars:
                return {'name': url[i + 1:]}
            else:
                count = 0
        else:
            count += 1
    return {'name': url}


class Handler(object):
    def __init__(self, environment):
        self.environment = environment


class DNSHandler(Handler):
    def process(self, pkg):
        if self.needs_processing(pkg):
            answers = get_dns_answers(pkg)
            for each in answers:
                self.environment.address_host[each] = pkg.dns.qry_name

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
            service = device.stream_to_service.get(stream)
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

    def search_service(self, pkg):
        service_characteristics = self.environment.service_analyzer.find_service_from_ip(
            pkg.ip.dst)
        if service_characteristics:
            return service_characteristics
        else:
            host = self.environment.find_host(pkg.ip.dst)
            if host:
                return self.environment.service_analyzer.find_service_from_absolute_url(
                    host
                ) or self.environment.service_analyzer.find_service_from_url(
                    host) or get_significant_service_from_url(host, 4)
            else:
                return None

    def process_new_stream(self, pkg):
        service_characteristics = self.search_service(pkg)

        if service_characteristics:
            self.process_new_detected_service(service_characteristics, pkg)
        else:
            self.environment.temporal_stream_map[self.get_protocol()][
                self.get_stream(pkg)] = [(pkg.sniff_time, pkg.length)]

    def process_new_detected_service(self, service_characteristics, pkg):
        service = self.environment.get_existing_authorless_service(
            service_characteristics['name'])

        if not service:
            service = AuthorlessService()
            service.characteristics = service_characteristics
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

        service = device.stream_to_service.get(pkg.tcp.stream)
        if service:
            service.add_activity(time, length)

    def process_new_stream(self, pkg):
        def action(device_args, app_args):
            device = self.solve_device(device_args, app_args)
            device.update(device_args, app_args, pkg.tcp.stream)

            self.environment.device_stream_map[Transport.TCP][
                pkg.tcp.stream] = device

            device.add_activity(pkg.sniff_time, pkg.length)

            service = device.stream_to_service.get(pkg.tcp.stream)

            if service:
                service.add_activity(pkg.sniff_time, pkg.length)

            if self.environment.has_temporal_stream(pkg):

                for each in self.environment.locate_temporal(pkg):
                    device.add_activity(each[0], each[1])
                    if service:
                        service.add_activity(each[0], each[1])

                del self.environment.temporal_stream_map[Transport.TCP][
                    pkg.tcp.stream]

            if self.environment.has_service_from_stream(pkg):

                existing_service = self.environment.locate_service(pkg)

                activity_from_stream = existing_service.activity_per_stream[
                    Transport.TCP][pkg.tcp.stream]

                device.merge_activity(activity_from_stream)
                if service:
                    service.merge_activity(activity_from_stream)

                # Only remove current stream for service,
                # not the whole service, as it could be consumed
                # by other devices also (think WhatsApp)

                existing_service.remove_activity_from_stream(Transport.TCP,
                                                             pkg.tcp.stream)

                del self.environment.service_stream_map[Transport.TCP][
                    pkg.tcp.stream]

                # Only remove authorless Service
                # if no streams are left associated with it
                if existing_service.is_empty():
                    self.environment.authorless_services.remove(
                        existing_service)

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
