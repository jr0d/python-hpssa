# Copyright 2015-2017 Jared Rodriguez (jared at blacknode dot net)
# Copyright 2017 Hussam Dawood
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# https://kallesplayground.wordpress.com/useful-stuff/hp-smart-array-cli-commands-under-esxi/ < This!
# https://community.hpe.com/hpeb/attachments/hpeb/itrc-264/148204/3/HP%20Smart%20Storage%20Administrator%20User%20Guide.pdf
#
# Parsing (scraping) this output is dangerous and calls into this class should
# be treated with extreme prejudice.
#
# THERE BE DRAGONS HERE
#
# TODO: Use ld show detail and pd all show detail to get more information about lds and pds
# TODO: Make this a complete replacement for all hpssacli functions
# TODO: relate active spares to failed drive index
#    ex: physicaldrive 1I:1:7 (port 1I:box 1:bay 7, SAS, 300 GB, OK, active spare for 1I:1:6)

import logging
import re

from ._cli import run, find_in_path
from size.size import Size, SizeObjectValError

LOG = logging.getLogger(__name__)


class HPRaidException(Exception):
    pass


class HPParserException(Exception):
    pass


def __extract_pci_address(line):
    return line.split()[-1].strip()


def __scrub_label(label):
    label = label.replace('(', '').replace(')', '').strip()
    return label.lower().replace(' ', '_')


def __parse_array_name(line):
    LOG.debug('Parsing array line: {}'.format(line))
    matches = re.match('^(?P<name>.*) in Slot (?P<slot>\d+)', line)
    LOG.debug('Found {} in slot {}'.format(matches.group('name'),
                                           matches.group('slot')))
    return {'name': matches.group('name'), 'slot': int(matches.group('slot'))}


def parse_adapter_details(raw_data):
    _adapters = []
    detail_indent = ' ' * 3

    array_details = None
    reached_adapter_details = False  # To help bypass `Controller:` messages
    for l in raw_data.splitlines():
        LOG.debug("-- raw --: {}".format(l))
        if not l:
            continue

        if not reached_adapter_details:
            if 'in Slot' in l:
                reached_adapter_details = True
            else:
                continue

        if l[:3] != detail_indent:  # ascii space
            if 'in Slot' in l:
                array_details = __parse_array_name(l)
                _adapters.append(array_details)
            elif re.match('^([A-Z].+)', l):  # errors are repoted in all caps
                try:
                    array_details['error'] = l.split(':', 1)[0]
                except IndexError:
                    array_details['error'] = l
                finally:
                    reached_adapter_details = False
            continue
        else:
            if 'PCI Address' in l:
                array_details['pci_address'] = __extract_pci_address(l)
                continue
            label, data = l.split(':', 1)
            array_details[__scrub_label(label)] = data.strip()

    return _adapters


def __parse_array_line(line):
    line = line.strip()

    array_info = {
        'letter': line.split()[1],
        'type': line.split()[3].strip('(,'),
        'free_space': Size(line.split(':')[1].strip().strip(')')).bytes
    }

    return array_info


def __parse_ld_line(line):
    line = line.strip()
    attributes = [x.strip()
                  for x in line.split('(')[1].strip(')').split(',')]
    raid_level = attributes[1].split()[1]
    if raid_level == '1+0':
        raid_level = 10
    else:
        raid_level = int(raid_level)

    progress = None
    if len(attributes) > 3 and '%' in attributes[3]:
        progress = float(attributes[3].split('%')[0].strip()) / 100

    ld_info = {
        'id': int(line.split()[1]),
        'size': Size(attributes[0]).bytes,
        'level': raid_level,
        'status': attributes[2],
        'progress': progress
    }

    return ld_info


def __parse_pd_line(line):
    line = line.strip()
    port, box, bay = line.split()[1].split(':')
    attributes = [x.strip()
                  for x in line.split('(')[1].strip(')').split(',')[1:]]
    disk_type, size, status = attributes[0], attributes[1], attributes[2]

    # Failed drives will sometimes report size using the string '???'
    try:
        size = Size(size).bytes
    except SizeObjectValError:
        size = None  # setting to none so that arithmetic operations will break
        # if this is not accounted for

    spare = 'spare' in attributes[3:]
    pd_info = {
        'port': port,
        'box': box,
        'bay': bay,
        'type': disk_type,
        'size': size,
        'status': status,
        'spare': spare
    }

    return pd_info


def _update_spare_list(array_info, spare_list, pd):
    for spare in spare_list:
        if spare['port'] == pd['port'] and \
                        spare['box'] == pd['box'] and \
                        spare['bay'] == pd['bay']:
            spare['arrays'].append(array_info['letter'])
            return
    _s = pd.copy()
    _s.update({'arrays': [array_info['letter']]})
    spare_list.append(_s)


def parse_show_config(config):
    _drive_indent = ' ' * 6
    _array_indent = ' ' * 3

    array_info = {}
    arrays = []
    unassigned_drives = False
    unassigned = []
    spares = []
    drives = []
    configuration = {
        'arrays': arrays, 'unassigned': unassigned, 'spares': spares
    }

    for line in config.splitlines():
        LOG.debug('-- line --: {}'.format(line))
        if line[:6] == _drive_indent:
            pd_info = None
            ld_info = None

            # What are we looking at?
            if 'physicaldrive' in line:
                pd_info = __parse_pd_line(line)
                drives.append(pd_info)
            elif 'logicaldrive' in line:
                ld_info = __parse_ld_line(line)
            else:
                raise HPParserException('Found something other than an ld or '
                                        'pd at indent level 6')

            if array_info:
                if pd_info:
                    if pd_info.pop('spare'):
                        _update_spare_list(array_info, spares, pd_info)
                    else:
                        array_info['physical_drives'].append(
                            pd_info
                        )

                elif ld_info:
                    array_info['logical_drives'].append(
                        ld_info
                    )

            if unassigned_drives:
                if pd_info:
                    unassigned.append(
                        pd_info
                    )

        if line[:3] == _array_indent:
            if line.find('array') == 3:
                if array_info:
                    arrays.append(array_info)

                array_info = __parse_array_line(line)
                array_info['physical_drives'] = []
                array_info['logical_drives'] = []
                continue

            if line.find('unassigned') == 3:
                if array_info:
                    arrays.append(array_info)
                array_info = None
                unassigned_drives = True
                continue

    # If there are no unassigned drives, we need to append the last array

    if not unassigned_drives:
        if array_info:
            arrays.append(array_info)

    return drives, configuration


def parse_drive_info(pd_info):
    details_indent = ' ' * 9
    pd_details = {}
    for line in pd_info.splitlines():
        if not line:
            continue

        if line.find(details_indent) == 0:
            label, data = line.split(':', 1)
            scrubbed_label = __scrub_label(label)
            if scrubbed_label == 'size':
                pd_details[scrubbed_label] = Size(data.strip()).bytes
            else:
                pd_details[scrubbed_label] = data.strip()

    return pd_details


class Adapter(dict):
    def __init__(self, *args, **kwargs):
        super(Adapter, self).__init__(*args, **kwargs)

    @property
    def total_drives(self):
        return len(self['drives'])

    @property
    def total_size(self):
        _bytes = 0
        for drive in self['drives']:
            _bytes += drive['size']
        return _bytes

    @property
    def unassigned_total(self):
        return len(self['configuration']['unassigned'])

    @property
    def unassigned_size(self):
        _bytes = 0
        for drive in self['configuration']['unassigned']:
            _bytes += drive['_size'].bytes
        return _bytes


def update_late(f):
    def wrapped(self, *args, **kwargs):
        result = f(self, *args, **kwargs)
        LOG.debug('Updating adapter data')
        self.refresh()
        return result

    return wrapped


class HPSSA(object):
    details_command = 'ctrl all show detail'
    parity_levels = [5, 6, 50, 60]

    def __init__(self, hpssa_path='hpssacli'):
        self.hpssacli_path = find_in_path(hpssa_path)
        self.adapters = []
        self.refresh()

    def run(self, cmd, ignore_error=False):
        result = run('%s %s' % (self.hpssacli_path, cmd),
                     ignore_error=ignore_error)
        if not ignore_error:
            if result.returncode:
                raise HPRaidException('Command returned: {}, Error: {}'.format(
                    result.returncode, result))
        return result

    def _get_raw_config(self, slot):
        cmd = 'ctrl slot=%s show config' % slot
        # TODO: TEST TEST TEST, check return and raise
        return self.run(cmd)

    def _raw_system_info(self):
        # TODO: TEST 1, run on system that is missing smart array devices
        # TODO: Check return code and raise an Exception when appropriate
        raw_details = self.run(self.details_command)

        adapters = parse_adapter_details(raw_details)

        for adapter in adapters:
            if adapter.get('error'):
                LOG.debug('Controller {} (slot {}) is in an error '
                          'state: {}'.format(adapter['name'],
                                             adapter['slot'],
                                             adapter['error']))
                continue
            _config = self._get_raw_config(adapter['slot'])
            adapter['drives'], adapter['configuration'] = \
                parse_show_config(_config)

        return [Adapter(**a) for a in adapters]

    def refresh(self):
        self.adapters = self._raw_system_info()

    def get_slot_details(self, slot):
        for adapter in self.adapters:
            # TODO: clean up adapter structure, so that ints are ints, OKs or bools, etc
            if int(slot) == int(adapter['slot']):
                return adapter
        raise HPRaidException('There is no adapter at slot {}'.format(slot))

    def cache_ok(self, slot):
        adapter = self.get_slot_details(slot)
        return adapter.get('cache_status') == 'OK'

    def get_arrays(self, slot):
        adapter = self.get_slot_details(slot)
        if adapter.get('error'):
            LOG.debug('Controller {} (slot {}) is in an error '
                      'state: {}'.format(adapter['name'],
                                         adapter['slot'],
                                         adapter['error']))
            return []
        return adapter['configuration']['arrays']

    def get_array_letters(self, slot):
        arrays = self.get_arrays(slot)
        if arrays:
            return [x['letter'] for x in arrays]

    def get_array(self, slot, letter):
        arrays = self.get_arrays(slot)
        for array in arrays:
            if array['letter'] == letter:
                return array
        raise HPRaidException(
            'Array {} does not exist on the adapter at slot {}'.format(
                letter, slot)
        )

    def get_drive(self, slot, drive_id):
        adapter = self.get_slot_details(slot)
        for drive in adapter['drives'] or []:
            _id = '%s:%s:%s' % (drive['port'], drive['box'], drive['bay'])
            if drive_id == _id:
                return drive

    def get_drive_index(self, slot, drive_id):
        adapter = self.get_slot_details(slot)
        if adapter.get('error'):
            LOG.debug('Controller {} (slot {}) is in an error '
                      'state: {}'.format(adapter['name'],
                                         adapter['slot'],
                                         adapter['error']))
        else:
            drives = adapter['drives']
            for idx in range(len(drives)):
                _id = '%s:%s:%s' % (drives[idx]['port'],
                                    drives[idx]['box'],
                                    drives[idx]['bay'])
                if drive_id == _id:
                    return idx
        return -1

    def get_firmware_version(self, slot):
        """
        Returns the first firmware version from the adapters list
        """
        adapter = self.get_slot_details(slot)
        return adapter.get('firmware_version')

    def get_drive_configuration(self):
        """
        Iterate through the adapters and grab all the drive configurations
        """
        drive_list = []
        for adapter in self.adapters:
            if 'slot' not in adapter or 'configuration' not in adapter:
                continue
            config = adapter['configuration']
            drive_list.append({'slot': adapter['slot'],
                               'drives': adapter['drives'],
                               'arrays': config.get('arrays', []),
                               'unassigned': config.get('unassigned', [])})
        return drive_list

    def get_all_drives(self):
        """
        Return a list of flat structure drives that includes the adapter
        slot and drive identifier
        """
        all_drives = []
        for drive_config in self.get_drive_configuration():
            for drive in drive_config['drives']:
                all_drives.append(dict(slot=drive_config['slot'],
                                       drive_id=self.assemble_id(drive),
                                       **drive))
        return all_drives

    def expand_id_range(self, slot, _id_range):
        """

        :param slot:
        :param _id_range:
        :return:
        """
        range_low, range_high = _id_range.split('-')
        start_idx = self.get_drive_index(slot, range_low)
        end_idx = self.get_drive_index(slot, range_high)

        if not (start_idx or end_idx):
            raise HPRaidException('Range is not valid')

        controller = self.get_slot_details(slot)
        if 'drives' not in controller:
            raise HPRaidException('No drives on controller {}'.format(slot))

        return controller['drives'][start_idx:end_idx + 1]

    def get_drives_from_selection(self, slot, s):
        adapter = self.get_slot_details(slot)
        if not adapter:
            return []

        if s == 'all':
            return adapter.get('drives') or []

        if s == 'allunassigned':
            return adapter.get('configuration', {}).get('unassigned') or []

        items = s.split(',')

        drives = []
        for idx in range(len(items)):
            if '-' in items[idx]:
                drives += self.expand_id_range(slot, items[idx])
                continue
            drives.append(self.get_drive(slot, items[idx]))

        return drives

    def get_array_drives(self, slot, array):
        array = self.get_array(slot, array)
        return array['physical_drives']

    @staticmethod
    def is_ssd(drive):
        return 'Solid State' in drive['type'] or 'SSD' in drive['type']

    def all_ssd(self, drives):
        for drive in drives:
            if not self.is_ssd(drive):
                return False
        return True

    @update_late
    def create(self, slot, selection=None, raid=None, array_letter=None,
               array_type='ld', size='max', stripe_size='default',
               write_policy='writeback', sectors=32, caching=True,
               data_ld=None, parity_init_method='default'):
        """
        Create an array, logical drive, or logical_cache_drive

        :param parity_init_method:
        :param array_letter:
        :param slot:
        :param selection: all, allunassigned, Port:Box:Bay,...  , 1I:1:1-1I:1:6
        :param raid: 0, 1, 5, 6, 1+0, 1+0asm, 50, 60
        :param array_type: ld, ldcache, arrayr0
        :param size: size in MB, min, max, maxmbr
        :param stripe_size: 2**3-10 (8-1024), default
        :param write_policy:
        :param sectors: 32, 64
        :param caching: True | False
        :param data_ld: ld ID, required if array_type == ldcache
        :return:
        """

        adapter = self.get_slot_details(slot)
        if adapter.get('error'):
            LOG.debug('Controller {} (slot {}) is in an error '
                      'state: {}'.format(adapter['name'],
                                         adapter['slot'],
                                         adapter['error']))
            return

        create_string = 'controller slot={} {}create'.format(
            slot, array_letter and 'array {} '.format(array_letter) or '')

        command = '{create_string} type={type}{drives}' \
                  '{raid} size={size} stripesize={stripe_size} forced'.format(
            **{
                'create_string': create_string,
                'slot': slot,
                'type': array_type,
                'drives': selection and ' drives={}'.format(selection) or '',
                'raid': raid and ' raid={}'.format(raid) or '',
                'size': size,
                'stripe_size': stripe_size
            })

        standard_array_options = {
            'sectors': sectors,
            'caching': caching and 'enable' or 'disable',
        }

        cache_array_options = {
            'datald': data_ld,
            'writepolicy': write_policy
        }

        ssd_array_options = {
            'ssdoverprovisioningoptimization': 'on'
        }

        parity_array_options = {
            'parityinitializationmethod': parity_init_method
        }

        build_options = \
            lambda o: ' %s' % ' '.join(['%s=%s' % (x, o[x]) for x in o])

        standard_array_types = ['ld', 'arrayr0']

        if array_type in standard_array_types:
            command += build_options(standard_array_options)

        elif array_type == 'ldcache':
            if not data_ld:
                raise HPRaidException('Type: ldcache requires data_ld')

            command += build_options(cache_array_options)

        else:
            raise HPRaidException('Type: %s is not supported' % array_type)

        if array_letter:
            test_drives = self.get_array_drives(slot, array_letter)
        else:
            test_drives = self.get_drives_from_selection(slot, selection)

        if self.all_ssd(test_drives):
            command += build_options(ssd_array_options)

        try:
            if int(raid) in self.parity_levels:
                command += build_options(parity_array_options)
        except ValueError:
            # 1+0 and 1+0asm will hit here
            pass

        LOG.info(
            'Creating LD - slot: {}, raid: {}, type: {} array: {}, '
            'selection: {}, size={}'.format(
                slot, raid, array_type, array_letter, selection, size)
        )
        LOG.debug('Running command: {}'.format(command))
        result = self.run(command)

        return result

    @update_late
    def delete_logical_drive(self, slot, ld):
        adapter = self.get_slot_details(slot)
        if adapter.get('error'):
            LOG.debug('Controller {} (slot {}) is in an error '
                      'state: {}'.format(adapter['name'],
                                         adapter['slot'],
                                         adapter['error']))
            return

        LOG.info('Deleting slot: %s, ld : %s' % (slot, ld))
        cmd = 'ctrl slot=%s ld %s delete forced' % (slot, ld)
        return self.run(cmd)

    @update_late
    def delete_all_logical_drives(self, slot):
        adapter = self.get_slot_details(slot)
        if adapter.get('error'):
            LOG.debug('Controller {} (slot {}) is in an error '
                      'state: {}'.format(adapter['name'],
                                         adapter['slot'],
                                         adapter['error']))
            return

        LOG.info('Deleting all logical drives on slot %s' % slot)
        cmd = 'ctrl slot=%s ld all delete forced' % slot
        return self.run(cmd, ignore_error=True)

    @update_late
    def add_spares(self, slot, array_letter, selection):
        adapter = self.get_slot_details(slot)
        if adapter.get('error'):
            LOG.debug('Controller {} (slot {}) is in an error '
                      'state: {}'.format(adapter['name'],
                                         adapter['slot'],
                                         adapter['error']))
            return

        LOG.info('Adding spare - slot: {}, array: {}, disks: {}'.format(
            slot, array_letter, selection))
        cmd = 'ctrl slot={} array {} add spares={}'.format(slot,
                                                           array_letter,
                                                           selection)
        return self.run(cmd)

    def clear_configuration(self):
        results = dict()
        for adapter in self.adapters:
            if 'error' in adapter:
                continue
            results[adapter['slot']] = \
                (self.delete_all_logical_drives(adapter['slot']))

        return results

    def get_pd_info(self, slot, pd):
        cmd = 'ctrl slot=%s pd %s show detail' % (slot, pd)
        adapter = self.get_slot_details(slot)
        if adapter.get('error'):
            LOG.debug('Controller {} (slot {}) is in an error '
                      'state: {}'.format(adapter['name'],
                                         adapter['slot'],
                                         adapter['error']))
            return {}
        return parse_drive_info(self.run(cmd))

    @staticmethod
    def assemble_id(pd_info):
        return '%s:%s:%s' % (pd_info['port'], pd_info['box'], pd_info['bay'])

    def get_pd_by_index(self, slot, idx):
        adapter = self.get_slot_details(slot)
        if adapter.get('error'):
            return ''
        pd_info = adapter['drives'][idx]
        return self.assemble_id(pd_info)


if __name__ == '__main__':
    import sys
    logging.basicConfig()
    LOG.setLevel(logging.DEBUG)
    raw_data = open(sys.argv[1]).read()
    print(parse_adapter_details(raw_data))
