from pathlib import Path
from lxml import etree
import json
from collections import OrderedDict
import argparse
import logging


class Build:

    def __init__(self, build_file_name, debug):

        self.builds_path = "builds/"
        self.debug = debug
        self.exclusions_path = "builds/exclusions/"
        self.inclusions_path = "builds/inclusions/"
        self.logs_path = "logs/"
        self.modules_path = "modules/"
        self.modules_identifier = "[0-9]*/*.xml"
        self.private_modules_identifier = "*/custom/*.xml"
        self.templates_path = "templates/"

        self.create_directories()
        self.load_build_file(build_file_name)


    def create_directories(self):

        # Make sure all paths are created
        for key in vars(self):
            if key.endswith("_path"):
                Path(getattr(self, key)).mkdir(exist_ok=True)

    
    def load_build_file(self, build_file_name) -> json:

        # Clean up input
        if self.builds_path in build_file_name:
            build_file_name = build_file_name.removeprefix(self.builds_path)

        build_file_path = Path(self.builds_path) / build_file_name

        if build_file_path.exists():

            with open(build_file_path.resolve()) as data:

                json_data = json.loads(data.read())

            try:
                # Set attributes in the object matching key / value pairs in the build file
                for key, value in json_data.items():
                    # Ensure key is not already defined in the default object
                    if key not in vars(self):
                        setattr(self, key, value)

            except Exception as exception:
                logging.critical(exception)
                raise ValueError(exception)
            
        else:
            message = f'The provided build file "{build_file_name}" does not exist.'
            logging.critical(message)
            raise FileNotFoundError(message)


def find_modules_in_modules_path(build) -> list:
    
    modules = []

    if Path(build.modules_path).is_dir():

        module_paths = list(Path(build.modules_path).glob(build.modules_identifier))

        for module_path in module_paths:

            modules.append(module_path.resolve())

        modules.sort()

        return modules

    else:
        message = f'The provided modules path "{build.modules_path}" does not exist.'
        logging.critical(message)
        raise FileNotFoundError(message)
    

def find_modules_in_options_lists(build, option_type) -> list:

    if option_type == "exclusions":
        option_lists = build.exclusions
        option_list_path_root = build.exclusions_path
    elif option_type == "inclusions":
        option_lists = build.inclusions
        option_list_path_root = build.inclusions_path

    option_modules = []

    for option_list in option_lists:

        option_list_path = Path(option_list_path_root) / option_list

        if option_list_path.exists():

            with open(str(option_list_path), 'r') as option_list_file:

                for line in option_list_file:

                    line = line.strip()

                    if build.modules_path not in line:

                        option_path = Path(build.modules_path) / line

                    else:

                        option_path = Path(line)

                    if option_path.exists():

                        option_modules.append(option_path.resolve())
                    
                    else:
                        message = f'The provided module "{line}" does not exist.'
                        logging.critical(message)
                        raise FileNotFoundError(message)
                    
        else:
            message = f'The provided {option_type} list file "{option_list}" does not exist.'
            logging.critical(message)
            raise FileNotFoundError(message)

    return option_modules


def remove_excluded_modules(modules, excluded_modules) -> list:

    filtered_modules = []

    for module in modules:

        if module not in excluded_modules:

            filtered_modules.append(module)

    return filtered_modules


def load_xml_for_all_modules(modules, remove_comments) -> list:

    list_of_module_xml = []

    for module in modules:

        list_of_module_xml.append(etree.parse(module, parser=etree.XMLParser(remove_blank_text=True, remove_comments=remove_comments)))

    if len(list_of_module_xml) < 2:
        message = 'At least 2 sysmon modules expected.'
        logging.critical(message)
        raise ValueError(message)

    return list_of_module_xml


def merge_sysmon_xml(source, diff, build) -> etree._ElementTree:

    Rules = OrderedDict({
        "ProcessCreate": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "FileCreateTime": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "NetworkConnect": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "ProcessTerminate": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "DriverLoad": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "ImageLoad": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "CreateRemoteThread": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "RawAccessRead": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "ProcessAccess": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "FileCreate": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "RegistryEvent": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "FileCreateStreamHash": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "PipeEvent": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "WmiEvent": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "DnsQuery": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "FileDelete": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "ClipboardChange": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "ProcessTampering": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "FileDeleteDetected": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "FileBlockExecutable": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "FileBlockShredding": OrderedDict({
            "include": [],
            "exclude": []
        }),
        "FileExecutableDetected": OrderedDict({
            "include": [],
            "exclude": []
        })
    })

    template_file_path = Path(build.templates_path) / build.template_file

    base_tree = etree.parse(template_file_path, parser=etree.XMLParser(remove_blank_text=True, remove_comments=build.remove_comments))

    base_root = base_tree.getroot()

    base_event_filtering = base_root.find("EventFiltering")

    # Strip disabled events from template file
    for event in build.disabled_events:
        for template_event in base_event_filtering.findall(".//RuleGroup/{}".format(event)):
            # Go from ProcessTerminate -> RuleGroup -> EventFiltering and remove the entire RuleGroup element
            template_rule_group = template_event.getparent()
            template_rule_group.getparent().remove(template_rule_group)

    for key in Rules.keys():
            
        if key not in build.disabled_events:

            for config in [source, diff]:

                for rule in config.findall(".//RuleGroup/{}".format(key)):

                    onmatch = rule.get('onmatch')

                    if onmatch is None:
                        onmatch = "include"

                    if onmatch not in Rules[key]:
                        Rules[key][onmatch] = []

                    Rules[key][onmatch].append(rule)


            for match_type in ['include', 'exclude']:

                for rule_element in Rules[key][match_type]:

                    xpath_expression = f".//RuleGroup/{key}[@onmatch = '{match_type}']"

                    # Find the element using XPath
                    existing = base_event_filtering.xpath(xpath_expression)

                    if len(existing) > 0:

                        for new_rule in rule_element:
                            existing[0].append(new_rule)

                    else:

                        # Find the RuleGroup based on the key
                        current_key_element = base_event_filtering.xpath(f".//RuleGroup/{key}")[0]
                        current_key_element_parent = current_key_element.getparent()

                        index = list(base_event_filtering).index(current_key_element_parent)

                        new_rule_group = etree.Element('RuleGroup', {'groupRelation': 'or'})
                        new_rule_group.append(rule_element)

                        if match_type == "include":
                            base_event_filtering.insert(index, new_rule_group)
                        else:
                            base_event_filtering.insert(index+1, new_rule_group)
                
    return base_tree
            

def generate_sysmon_config(build):
    
    if build.inclusions:

        logging.info(f'Inclusions specified. Only included modules will be loaded. Attempting to locate {len(build.inclusions)} inclusion lists in "{build.inclusions_path}".')

        # Only find modules specified in inclusion lists
        modules = find_modules_in_options_lists(build, "inclusions")

        logging.info(f'Returned {len(modules)} included modules.')
        
        if build.debug:
            for module in modules:
                logging.debug(f'Included: {module}.')

    else:

        logging.info(f'Attempting to locate all modules in "{build.modules_path}" using the glob pattern "{build.modules_identifier}".')

        # Find all modules in MODULES_PATH using MODULE_IDENTIFIER
        modules = find_modules_in_modules_path(build)

        logging.info(f'Returned {len(modules)} identified module paths.')

        if build.debug:
            for module in modules:
                logging.debug(f'Identified: {module}.')

    if build.exclusions:

        logging.info(f'Exclusions specified. Excluded modules will be removed from the configuration. Attempting to locate {len(build.exclusions)} exclusion lists in "{build.exclusions_path}".')

        # Find all modules to be excluded
        excluded_modules = find_modules_in_options_lists(build, "exclusions")

        logging.info(f'Returned {len(excluded_modules)} excluded modules.')

        # Remove excluded modules
        modules = remove_excluded_modules(modules, excluded_modules)

        logging.info(f'Removed {len(excluded_modules)} excluded modules, {len(modules)} remaining.')

        if build.debug:
            for excluded_module in excluded_modules:
                logging.debug(f'Excluded: {excluded_module}.')
            for module in modules:
                logging.debug(f'Remaining: {module}.')

    if build.remove_private_modules:

        logging.info(f'Remove private modules set to True. Private modules will be removed from the configuration. Attempting to locate all private modules in "{build.modules_path}" using the glob pattern "{build.private_modules_identifier}".')

        private_modules = list(Path(build.modules_path).glob(build.private_modules_identifier))

        logging.info(f'Returned {len(private_modules)} private modules.')

        # Remove excluded modules
        modules = remove_excluded_modules(modules, private_modules)

        logging.info(f'Removed {len(private_modules)} private modules, {len(modules)} remaining.')

        if build.debug:
            for private_module in private_modules:
                logging.debug(f'Excluded: {private_module}.')
            for module in modules:
                logging.debug(f'Remaining: {module}.')

    # Load XML for each module
    list_of_module_xml = load_xml_for_all_modules(modules, build.remove_comments)

    logging.info(f'Loaded {len(list_of_module_xml)} modules.')

    # Merge the XML from each module together
    sysmon_config = list_of_module_xml[0]

    logging.info(f'Merging {len(list_of_module_xml)} modules.')

    for i in range(1, len(list_of_module_xml)):
        sysmon_config = merge_sysmon_xml(sysmon_config, list_of_module_xml[i], build)
    
    sysmon_config.write(build.name, pretty_print=True)

    logging.info(f'Saved the merged configuration to {build.name}.')


def setup_logging(build):

    log_name = f"{build.logs_path}{build.name}".replace('.', '_')

    if build.debug:
        log_level = logging.DEBUG
        log_name += "_debug"
    else:
        log_level = logging.INFO

    logging.basicConfig(
        filename=(log_name + ".log"),
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    logging.info(f'''\n=====================================\n  {build.name.upper()}\n=====================================''')

    if build.debug:
        logging.debug(f'Debug logging set to {build.debug}.')


def main():

    parser = argparse.ArgumentParser(description="Merge Sysmon modules into a consolidated configuration file.")

    # Argument for build file
    parser.add_argument("-b", "--build", type=str, required=True, help="Select build file for the configuration.")

    # Argument for debugging (boolean)
    parser.add_argument("-d", "--debug", action="store_true", help="Enables debug logging.")
    
    args = parser.parse_args()

    build = Build(args.build, args.debug)

    setup_logging(build)

    logging.info(f'Generating {build.name} configuration file. Exclusions: {build.exclusions}. Inclusions: {build.inclusions}.')

    generate_sysmon_config(build)


if __name__ == "__main__":

    main()

