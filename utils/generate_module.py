from lxml import etree
from pathlib import Path
import argparse

MODULE_TEMPLATE_STAGING_PATH = "staging/"

Events = {
    "ProcessCreate": 1,
    "FileCreateTime": 2,
    "NetworkConnect": 3,
    "ProcessTerminate": 5,
    "DriverLoad": 6,
    "ImageLoad": 7,
    "CreateRemoteThread": 8,
    "RawAccessRead": 9,
    "ProcessAccess": 10,
    "FileCreate": 11,
    "RegistryEvent": 12,
    "RegistryEvent": 13,
    "RegistryEvent": 14,
    "FileCreateStreamHash": 15,
    "PipeEvent": 17,
    "PipeEvent": 18,
    "WmiEvent": 19,
    "WmiEvent": 20,
    "WmiEvent": 21,
    "DnsQuery": 22,
    "FileDelete": 23,
    "ClipboardChange": 24,
    "ProcessTampering": 25,
    "FileDeleteDetected": 26,
    "FileBlockExecutable": 27,
    "FileBlockShredding": 28,
    "FileExecutableDetected": 29
}


def generate_module(event, name, exclude=False, include=False):

    # Create the root element
    root = etree.Element("Sysmon", schemaversion="4.30")

    # Create EventFiltering element
    event_filtering_element = etree.SubElement(root, "EventFiltering")

    # Create RuleGroup element and append it to EventFiltering
    rule_group_element = etree.SubElement(event_filtering_element, "RuleGroup", name="", groupRelation="or")

    if exclude:
        onmatch = "exclude"
        groupRelation = "and"
    elif include:
        onmatch="include"
        groupRelation = "or"
    else:
        raise ValueError(f'Either an "exclude" or "include" statement must be specified.')
    
    # Create ProcessCreate element and append it to RuleGroup
    event_element = etree.SubElement(rule_group_element, event, onmatch=onmatch)

    # Create Rule element and append it to ProcessCreate
    rule_element = etree.SubElement(event_element, "Rule", groupRelation=groupRelation)

    # Create the XML string representation
    xml_string = etree.tostring(root, pretty_print=True, encoding="utf-8").decode("utf-8")

    print(xml_string)

    # Create the ElementTree
    tree = etree.ElementTree(root)

    # Ensure staging folder is created
    Path(MODULE_TEMPLATE_STAGING_PATH).mkdir(exist_ok=True)

    output_file_path = Path(MODULE_TEMPLATE_STAGING_PATH) / f"{onmatch}_{name}.xml"

    # Output the XML
    tree.write(output_file_path, pretty_print=True)


def validate_selection(event):

    if isinstance(int(event), int):

        for key,value in Events.items():

            if value == int(event):

                return key

    else:

        if event in Events.keys():

            return event
        
    raise ValueError(f'Unable to create a template for the event "{event}".')


def parse_arguments():

    parser = argparse.ArgumentParser(description="Generate a XML module template for a given event.")

    # Argument for events by code / name
    parser.add_argument("-c", "--code", type=str, required=True, help=f"Select a Sysmon event by code or name. Ex: 1 or ProcessCreate")

    # Argument for events by name
    parser.add_argument("-e", "--exclude", action="store_true", help=f"Create an exclude statement template.")

    # Argument for inclusions (list of file names)
    parser.add_argument("-i", "--include", action="store_true", help=f"Create an include statement template")

    # Argument for name (output name as a string)
    parser.add_argument("-n", "--name", type=str, required=True, help="Name of the new module.")

    args = parser.parse_args()

    return args


if __name__ == "__main__":
    
    args = parse_arguments()

    event = validate_selection(args.code)

    generate_module(event, args.name, args.exclude, args.include)