#!/usr/bin/env python
import optparse
import os
import sys
import zipfile

"""
Take a MaxMind GeoLite Country database as input and replace A1 entries
with the country code and name of the preceding entry iff the preceding
(subsequent) entry ends (starts) directly before (after) the A1 entry and
both preceding and subsequent entries contain the same country code.

Then apply manual changes, either replacing A1 entries that could not be
replaced automatically or overriding previously made automatic changes.
"""

def main():
    options = parse_options()
    assignments = read_file(options.in_maxmind)
    assignments = apply_automatic_changes(assignments)
    write_file(options.out_automatic, assignments)
    manual_assignments = read_file(options.in_manual, must_exist=False)
    assignments = apply_manual_changes(assignments, manual_assignments)
    write_file(options.out_manual, assignments)
    write_file(options.out_geoip, assignments, long_format=False)

def parse_options():
    parser = optparse.OptionParser()
    parser.add_option('-i', action='store', dest='in_maxmind',
            default='GeoIPCountryCSV.zip', metavar='FILE',
            help='use the specified MaxMind GeoLite Country .zip or .csv '
                 'file as input [default: %default]')
    parser.add_option('-g', action='store', dest='in_manual',
            default='geoip-manual', metavar='FILE',
            help='use the specified .csv file for manual changes or to '
                 'override automatic changes [default: %default]')
    parser.add_option('-a', action='store', dest='out_automatic',
            default="AutomaticGeoIPCountryWhois.csv", metavar='FILE',
            help='write full input file plus automatic changes to the '
                 'specified .csv file [default: %default]')
    parser.add_option('-m', action='store', dest='out_manual',
            default='ManualGeoIPCountryWhois.csv', metavar='FILE',
            help='write full input file plus automatic and manual '
                 'changes to the specified .csv file [default: %default]')
    parser.add_option('-o', action='store', dest='out_geoip',
            default='geoip', metavar='FILE',
            help='write full input file plus automatic and manual '
                 'changes to the specified .csv file that can be shipped '
                 'with tor [default: %default]')
    (options, args) = parser.parse_args()
    return options

def read_file(path, must_exist=True):
    if not os.path.exists(path):
        if must_exist:
            print 'File %s does not exist.  Exiting.' % (path, )
            sys.exit(1)
        else:
            return
    if path.endswith('.zip'):
        zip_file = zipfile.ZipFile(path)
        csv_content = zip_file.read('GeoIPCountryWhois.csv')
        zip_file.close()
    else:
        csv_file = open(path)
        csv_content = csv_file.read()
        csv_file.close()
    assignments = []
    for line in csv_content.split('\n'):
        stripped_line = line.strip()
        if len(stripped_line) > 0 and not stripped_line.startswith('#'):
            assignments.append(stripped_line)
    return assignments

def apply_automatic_changes(assignments):
    print '\nApplying automatic changes...'
    result_lines = []
    prev_line = None
    a1_lines = []
    for line in assignments:
        if '"A1"' in line:
            a1_lines.append(line)
        else:
            if len(a1_lines) > 0:
                new_a1_lines = process_a1_lines(prev_line, a1_lines, line)
                for new_a1_line in new_a1_lines:
                    result_lines.append(new_a1_line)
                a1_lines = []
            result_lines.append(line)
            prev_line = line
    if len(a1_lines) > 0:
        new_a1_lines = process_a1_lines(prev_line, a1_lines, None)
        for new_a1_line in new_a1_lines:
            result_lines.append(new_a1_line)
    return result_lines

def process_a1_lines(prev_line, a1_lines, next_line):
    if not prev_line or not next_line:
        return a1_lines   # Can't merge first or last line in file.
    if len(a1_lines) > 1:
        return a1_lines   # Can't merge more than 1 line at once.
    a1_line = a1_lines[0].strip()
    prev_entry = parse_line(prev_line)
    a1_entry = parse_line(a1_line)
    next_entry = parse_line(next_line)
    touches_prev_entry = int(prev_entry['end_num']) + 1 == \
            int(a1_entry['start_num'])
    touches_next_entry = int(a1_entry['end_num']) + 1 == \
            int(next_entry['start_num'])
    same_country_code = prev_entry['country_code'] == \
            next_entry['country_code']
    if touches_prev_entry and touches_next_entry and same_country_code:
        new_line = format_line_with_other_country(a1_entry, prev_entry)
        print '-%s\n+%s' % (a1_line, new_line, )
        return [new_line]
    else:
        return a1_lines

def parse_line(line):
    if not line:
        return None
    keys = ['start_str', 'end_str', 'start_num', 'end_num',
            'country_code', 'country_name']
    stripped_line = line.replace('"', '').strip()
    parts = stripped_line.split(',')
    entry = dict((k, v) for k, v in zip(keys, parts))
    return entry

def format_line_with_other_country(original_entry, other_entry):
    return '"%s","%s","%s","%s","%s","%s"' % (original_entry['start_str'],
            original_entry['end_str'], original_entry['start_num'],
            original_entry['end_num'], other_entry['country_code'],
            other_entry['country_name'], )

def apply_manual_changes(assignments, manual_assignments):
    if not manual_assignments:
        return assignments
    print '\nApplying manual changes...'
    manual_dict = {}
    for line in manual_assignments:
        start_num = parse_line(line)['start_num']
        if start_num in manual_dict:
            print ('Warning: duplicate start number in manual '
                   'assignments:\n  %s\n  %s\nDiscarding first entry.' %
                   (manual_dict[start_num], line, ))
        manual_dict[start_num] = line
    result = []
    for line in assignments:
        entry = parse_line(line)
        start_num = entry['start_num']
        if start_num in manual_dict:
            manual_line = manual_dict[start_num]
            manual_entry = parse_line(manual_line)
            if entry['start_str'] == manual_entry['start_str'] and \
                    entry['end_str'] == manual_entry['end_str'] and \
                    entry['end_num'] == manual_entry['end_num']:
                if len(manual_entry['country_code']) != 2:
                    print '-%s' % (line, )  # only remove, don't replace
                else:
                    new_line = format_line_with_other_country(entry,
                            manual_entry)
                    print '-%s\n+%s' % (line, new_line, )
                    result.append(new_line)
                del manual_dict[start_num]
            else:
                print ('Warning: only partial match between '
                       'original/automatically replaced assignment and '
                       'manual assignment:\n  %s\n  %s\nNot applying '
                       'manual change.' % (line, manual_line, ))
                result.append(line)
        else:
            result.append(line)
    if len(manual_dict) > 0:
        print ('Warning: could not apply all manual assignments:  %s' %
                ('\n  '.join(manual_dict.values())), )
    return result

def write_file(path, assignments, long_format=True):
    if long_format:
        output_lines = assignments
    else:
        output_lines = []
        for long_line in assignments:
            entry = parse_line(long_line)
            short_line = "%s,%s,%s" % (entry['start_num'],
                    entry['end_num'], entry['country_code'], )
            output_lines.append(short_line)
    out_file = open(path, 'w')
    out_file.write('\n'.join(output_lines))
    out_file.close()

if __name__ == '__main__':
    main()

