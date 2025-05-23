import cockpit from "cockpit";
import React from "react";
import {
	Button,
	Form,
	FormHelperText,
	Grid,
	GridItem,
	Modal,
	ModalVariant,
	TextInput,
	NumberInput,
	ValidatedOptions
} from '@patternfly/react-core';
import {
	Select,
	SelectVariant,
	SelectOption
} from '@patternfly/react-core/deprecated';
import PropTypes from "prop-types";
import PluginBasicConfig from "./pluginBasicConfig.jsx";
import { listsEqual, log_cmd, valid_dn, file_is_path } from "../tools.jsx";
import { DoubleConfirmModal } from "../notifications.jsx";

const _ = cockpit.gettext;

class ReferentialIntegrity extends React.Component {
    componentDidMount(prevProps) {
        if (this.props.wasActiveList.includes(5)) {
            if (this.state.firstLoad) {
                this.updateFields();
            }
        }
    }

    componentDidUpdate(prevProps) {
        if (this.props.rows !== prevProps.rows) {
            this.updateFields();
        }
    }

    constructor(props) {
        super(props);

        this.state = {
            firstLoad: true,
            newEntry: true,
            isConfigMembershipAttrOpen: false,
            isMembershipAttrOpen: false,
            configEntryModalShow: false,
            saveBtnDisabled: true,
            saveBtnDisabledModal: true,
            saving: false,
            savingModal: false,
            modalSpinning: false,
            modalChecked: false,
            error: {},
            errorModal: {},
            showConfirmDelete: false,
            addSpinning: false,

            // Main settings
            updateDelay: "",
            membershipAttr: [],
            entryScope: "",
            excludeEntryScope: "",
            containerScope: "",
            logFile: "",
            referintConfigEntry: "",
            _updateDelay: "",
            _membershipAttr: [],
            _entryScope: "",
            _excludeEntryScope: "",
            _containerScope: "",
            _logFile: "",
            _referintConfigEntry: "",

            // Shared Config settings
            configDN: "",
            configUpdateDelay: "",
            configMembershipAttr: [],
            configEntryScope: "",
            configExcludeEntryScope: "",
            configContainerScope: "",
            configLogFile: "",
            _configDN: "",
            _configUpdateDelay: "",
            _configMembershipAttr: [],
            _configEntryScope: "",
            _configExcludeEntryScope: "",
            _configContainerScope: "",
            _configLogFile: "",
        };

        // Config Membership Attribute
        this.handleConfigMembershipAttrSelect = (event, selection) => {
            if (this.state.configMembershipAttr.includes(selection)) {
                this.setState(
                    (prevState) => ({
                        configMembershipAttr: prevState.configMembershipAttr.filter((item) => item !== selection),
                        isConfigMembershipAttrOpen: false
                    }), () => { this.validateModal() }
                );
            } else {
                this.setState(
                    (prevState) => ({
                        configMembershipAttr: [...prevState.configMembershipAttr, selection],
                        isConfigMembershipAttrOpen: false
                    }), () => { this.validateModal() }
                );
            }
        };
        this.handleConfigMembershipAttrToggle = (_event, isConfigMembershipAttrOpen) => {
            this.setState({
                isConfigMembershipAttrOpen
            });
        };
        this.handleConfigMembershipAttrClear = () => {
            this.setState({
                configMembershipAttr: [],
                isConfigMembershipAttrOpen: false
            });
        };

        // Membership Attribute
        this.handleMembershipAttrSelect = (event, selection) => {
            if (this.state.membershipAttr.includes(selection)) {
                this.setState(
                    (prevState) => ({
                        membershipAttr: prevState.membershipAttr.filter((item) => item !== selection),
                        isMembershipAttrOpen: false
                    }), () => { this.validateConfig() }
                );
            } else {
                this.setState(
                    (prevState) => ({
                        membershipAttr: [...prevState.membershipAttr, selection],
                        isMembershipAttrOpen: false
                    }),
                    () => { this.validateConfig() }
                );
            }
        };
        this.handleMembershipAttrToggle = (_event, isMembershipAttrOpen) => {
            this.setState({
                isMembershipAttrOpen
            });
        };
        this.handleMembershipAttrClear = () => {
            this.setState({
                membershipAttr: [],
                isMembershipAttrOpen: false
            });
        };

        this.maxValue = 20000000;
        this.onMinusConfig = (id) => {
            this.setState({
                [id]: Number(this.state[id]) - 1
            }, () => { this.validateConfig() });
        };
        this.onConfigChange = (event, id, min) => {
            const newValue = isNaN(event.target.value) ? 0 : Number(event.target.value);
            this.setState({
                [id]: newValue > this.maxValue ? this.maxValue : newValue < min ? min : newValue
            }, () => { id.startsWith("config") ? this.validateModal() : this.validateConfig() });
        };
        this.onPlusConfig = (id) => {
            this.setState({
                [id]: Number(this.state[id]) + 1
            }, () => { this.validateConfig() });
        };

        this.updateFields = this.updateFields.bind(this);
        this.onChange = this.onChange.bind(this);
        this.handleFieldChange = this.handleFieldChange.bind(this);
        this.handleModalChange = this.handleModalChange.bind(this);
        this.handleOpenModal = this.handleOpenModal.bind(this);
        this.handleCloseModal = this.handleCloseModal.bind(this);
        this.handleAddConfig = this.handleAddConfig.bind(this);
        this.handleEditConfig = this.handleEditConfig.bind(this);
        this.deleteConfig = this.deleteConfig.bind(this);
        this.cmdConfigOperation = this.cmdConfigOperation.bind(this);
        this.validateConfig = this.validateConfig.bind(this);
        this.validateModal = this.validateModal.bind(this);
        this.handleSaveConfig = this.handleSaveConfig.bind(this);
        this.handleShowConfirmDelete = this.handleShowConfirmDelete.bind(this);
        this.closeConfirmDelete = this.closeConfirmDelete.bind(this);
    }

    handleShowConfirmDelete() {
        this.setState({
            showConfirmDelete: true,
            modalChecked: false,
            modalSpinning: false,
        });
    }

    closeConfirmDelete() {
        this.setState({
            showConfirmDelete: false,
            modalChecked: false,
            modalSpinning: false,
        });
    }

    validateConfig() {
        const errObj = {};
        let all_good = true;
        const dnAttrs = [
            'entryScope', 'excludeEntryScope', 'containerScope', 'referintConfigEntry'
        ];
        const reqAttrs = ['logFile'];

        for (const attr of dnAttrs) {
            errObj[attr] = false;
            if (this.state[attr] !== "" && !valid_dn(this.state[attr])) {
                errObj[attr] = true;
                all_good = false;
            }
        }
        for (const attr of reqAttrs) {
            if (this.state[attr] === "") {
                errObj[attr] = true;
                all_good = false;
            }
        }

        if (!file_is_path(this.state.logFile)) {
            errObj.logFile = true;
            all_good = false;
        }

        errObj.membershipAttr = false;
        if (this.state.membershipAttr.length === 0) {
            errObj.membershipAttr = true;
            all_good = false;
        }
        if (all_good) {
            // Check for value differences to see if the save btn should be enabled
            all_good = false;
            const attrs = [
                'entryScope', 'excludeEntryScope', 'containerScope',
                'referintConfigEntry', 'updateDelay', 'logFile'
            ];
            for (const check_attr of attrs) {
                if (this.state[check_attr] !== this.state['_' + check_attr]) {
                    all_good = true;
                    break;
                }
            }
            if (!listsEqual(this.state.membershipAttr, this.state._membershipAttr)) {
                all_good = true;
            }
        }
        this.setState({
            saveBtnDisabled: !all_good,
            error: errObj
        });
        return all_good;
    }

    validateModal() {
        const errObj = {};
        let all_good = true;
        const dnAttrs = [
            'configDN', 'configEntryScope', 'configExcludeEntryScope',
            'configContainerScope'
        ];
        const reqAttrs = ['configDN', 'configLogFile'];

        for (const attr of dnAttrs) {
            if (this.state[attr] !== "" && !valid_dn(this.state[attr])) {
                errObj[attr] = true;
                all_good = false;
            }
        }
        for (const attr of reqAttrs) {
            if (this.state[attr] === "") {
                errObj[attr] = true;
                all_good = false;
            }
        }
        if (!file_is_path(this.state.configLogFile)) {
            errObj.configLogFile = true;
            all_good = false;
        }

        errObj.configMembershipAttr = false;
        if (this.state.configMembershipAttr.length === 0) {
            errObj.configMembershipAttr = true;
            all_good = false;
        }
        if (all_good) {
            // Check for value differences to see if the save btn should be enabled
            all_good = false;
            const attrs = [
                'configDN', 'configEntryScope', 'configExcludeEntryScope',
                'configContainerScope', 'configUpdateDelay'
            ];
            for (const check_attr of attrs) {
                if (this.state[check_attr] !== this.state['_' + check_attr]) {
                    all_good = true;
                    break;
                }
            }
            if (!listsEqual(this.state.configMembershipAttr, this.state._configMembershipAttr)) {
                all_good = true;
            }
        }
        this.setState({
            saveBtnDisabledModal: !all_good,
            errorModal: errObj
        });
    }

    onChange(e) {
        // Generic handler for things that don't need validating
        const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
        this.setState({
            [e.target.id]: value,
        });
    }

    handleFieldChange(e) {
        this.setState({
            [e.target.id]: e.target.value,
        }, () => { this.validateConfig() });
    }

    handleModalChange(e) {
        this.setState({
            [e.target.id]: e.target.value,
        }, () => { this.validateModal() });
    }

    handleSaveConfig() {
        const {
            membershipAttr,
            entryScope,
            excludeEntryScope,
            containerScope,
            logFile,
            referintConfigEntry,
        } = this.state;
        const updateDelay = this.state.updateDelay.toString();

        let cmd = [
            "dsconf",
            "-j",
            "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "plugin",
            "referential-integrity",
            "set",
            "--update-delay",
            updateDelay || "delete",
            "--entry-scope",
            entryScope || "delete",
            "--exclude-entry-scope",
            excludeEntryScope || "delete",
            "--container-scope",
            containerScope || "delete",
            "--config-entry",
            referintConfigEntry || "delete",
            "--log-file",
            logFile || "delete"
        ];

        // Delete attributes if the user set an empty value to the field
        cmd = [...cmd, "--membership-attr"];
        if (membershipAttr.length !== 0) {
            for (const value of membershipAttr) {
                cmd = [...cmd, value];
            }
        } else {
            cmd = [...cmd, "delete"];
        }

        this.setState({
            saving: true
        });

        log_cmd(
            "handleSaveConfig",
            `Save Referential Integrity Plugin`,
            cmd
        );
        cockpit
                .spawn(cmd, {
                    superuser: true,
                    err: "message"
                })
                .done(content => {
                    console.info("referintOperation", "Result", content);
                    this.props.addNotification(
                        "success",
                        _("Successfully updated Referential Integrity Plugin")
                    );
                    this.setState({
                        saving: false
                    });
                    this.props.pluginListHandler();
                })
                .fail(err => {
                    let errMsg = JSON.parse(err);
                    if ('info' in errMsg) {
                        errMsg = errMsg.desc + " " + errMsg.info;
                    } else {
                        errMsg = errMsg.desc;
                    }
                    this.props.addNotification(
                        "error", cockpit.format(_("Error during update - $0"), errMsg)
                    );
                    this.setState({
                        saving: false
                    });
                    this.props.pluginListHandler();
                });
    }

    handleOpenModal() {
        if (!this.state.referintConfigEntry) {
            this.setState({
                configEntryModalShow: true,
                newEntry: true,
                configDN: "",
                configUpdateDelay: "0",
                configMembershipAttr: [],
                configEntryScope: "",
                configExcludeEntryScope: "",
                configContainerScope: "",
                configLogFile: "",
                _configDN: "",
                _configUpdateDelay: "",
                _configMembershipAttr: [],
                _configEntryScope: "",
                _configExcludeEntryScope: "",
                _configContainerScope: "",
                _configLogFile: "",
                addSpinning: false,
                savingModal: false,
            });
        } else {
            let membershipAttrList = [];
            const cmd = [
                "dsconf",
                "-j",
                "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
                "plugin",
                "referential-integrity",
                "config-entry",
                "show",
                this.state.referintConfigEntry
            ];

            log_cmd("handleOpenModal", "Fetch the Referential Integrity Plugin config entry", cmd);
            cockpit
                    .spawn(cmd, {
                        superuser: true,
                        err: "message"
                    })
                    .done(content => {
                        const pluginRow = JSON.parse(content).attrs;
                        this.setState({
                            configEntryModalShow: true,
                            newEntry: false,
                            configDN: this.state.referintConfigEntry,
                            configUpdateDelay:
                            pluginRow["referint-update-delay"] === undefined
                                ? ""
                                : pluginRow["referint-update-delay"][0],
                            configEntryScope:
                            pluginRow["nsslapd-pluginentryscope"] === undefined
                                ? ""
                                : pluginRow["nsslapd-pluginentryscope"][0],
                            configExcludeEntryScope:
                            pluginRow["nsslapd-pluginexcludeentryscope"] === undefined
                                ? ""
                                : pluginRow["nsslapd-pluginexcludeentryscope"][0],
                            configContainerScope:
                            pluginRow["nsslapd-plugincontainerscope"] === undefined
                                ? ""
                                : pluginRow["nsslapd-plugincontainerscope"][0],
                            configLogFile:
                            pluginRow["referint-logfile"] === undefined
                                ? ""
                                : pluginRow["referint-logfile"][0],
                            _configUpdateDelay:
                            pluginRow["referint-update-delay"] === undefined
                                ? ""
                                : pluginRow["referint-update-delay"][0],
                            _configEntryScope:
                            pluginRow["nsslapd-pluginentryscope"] === undefined
                                ? ""
                                : pluginRow["nsslapd-pluginentryscope"][0],
                            _configExcludeEntryScope:
                            pluginRow["nsslapd-pluginexcludeentryscope"] === undefined
                                ? ""
                                : pluginRow["nsslapd-pluginexcludeentryscope"][0],
                            _configContainerScope:
                            pluginRow["nsslapd-plugincontainerscope"] === undefined
                                ? ""
                                : pluginRow["nsslapd-plugincontainerscope"][0],
                            _configLogFile:
                            pluginRow["referint-logfile"] === undefined
                                ? ""
                                : pluginRow["referint-logfile"][0],
                        });

                        if (pluginRow["referint-membership-attr"] === undefined) {
                            this.setState({
                                configMembershipAttr: [],
                                _configMembershipAttr: [],
                            });
                        } else {
                            for (const value of pluginRow["referint-membership-attr"]) {
                                membershipAttrList = [...membershipAttrList, value];
                            }
                            this.setState({
                                configMembershipAttr: membershipAttrList,
                                _configMembershipAttr: [...membershipAttrList],
                            });
                        }
                    })
                    .fail(_ => {
                        this.setState({
                            configEntryModalShow: true,
                            newEntry: true,
                            configDN: this.state.referintConfigEntry,
                            configUpdateDelay: "0",
                            configMembershipAttr: [],
                            configEntryScope: "",
                            configExcludeEntryScope: "",
                            configContainerScope: "",
                            configLogFile: "",
                            _configDN: this.state.referintConfigEntry,
                            _configUpdateDelay: "",
                            _configMembershipAttr: [],
                            _configEntryScope: "",
                            _configExcludeEntryScope: "",
                            _configContainerScope: "",
                            _configLogFile: "",
                            savingModal: false,
                        });
                    });
        }
    }

    handleCloseModal() {
        this.setState({
            configEntryModalShow: false,
            savingModal: false,
            addSpinning: false,
            modalSpinning: false,
        });
    }

    cmdConfigOperation(action) {
        const {
            configDN,
            configUpdateDelay,
            configMembershipAttr,
            configEntryScope,
            configExcludeEntryScope,
            configContainerScope,
            configLogFile
        } = this.state;

        let cmd = [
            "dsconf",
            "-j",
            "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "plugin",
            "referential-integrity",
            "config-entry",
            action,
            configDN,
            "--update-delay",
            configUpdateDelay || action === "add" ? configUpdateDelay : "delete",
            "--entry-scope",
            configEntryScope || action === "add" ? configEntryScope : "delete",
            "--exclude-entry-scope",
            configExcludeEntryScope || action === "add" ? configExcludeEntryScope : "delete",
            "--container-scope",
            configContainerScope || action === "add" ? configContainerScope : "delete",
            "--log-file",
            configLogFile || action === "add" ? configLogFile : "delete"
        ];

        // Delete attributes if the user set an empty value to the field
        cmd = [...cmd, "--membership-attr"];
        if (configMembershipAttr.length !== 0) {
            for (const value of configMembershipAttr) {
                cmd = [...cmd, value];
            }
        } else if (action === "add") {
            cmd = [...cmd, ""];
        } else {
            cmd = [...cmd, "delete"];
        }

        let spinning = "savingModal";
        if (action === "add") {
            spinning = "addSpinning";
        }

        this.setState({
            [spinning]: true
        });

        log_cmd(
            "referintOperation",
            `Do the ${action} operation on the Referential Integrity Plugin`,
            cmd
        );
        cockpit
                .spawn(cmd, {
                    superuser: true,
                    err: "message"
                })
                .done(content => {
                    console.info("referintOperation", "Result", content);
                    this.props.addNotification(
                        "success",
                        cockpit.format(_("Config entry $0 was successfully $1"), configDN, action + "ed")
                    );
                    this.props.pluginListHandler();
                    this.handleCloseModal();
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error during the config entry $0 operation - $1"), action, errMsg.desc)
                    );
                    this.props.pluginListHandler();
                    this.handleCloseModal();
                });
    }

    deleteConfig() {
        const cmd = [
            "dsconf",
            "-j",
            "ldapi://%2fvar%2frun%2fslapd-" + this.props.serverId + ".socket",
            "plugin",
            "referential-integrity",
            "config-entry",
            "delete",
            this.state.configDN
        ];
        this.setState({
            modalSpinning: true,
        });
        log_cmd("deleteConfig", "Delete the Referential Integrity Plugin config entry", cmd);
        cockpit
                .spawn(cmd, {
                    superuser: true,
                    err: "message"
                })
                .done(content => {
                    console.info("deleteConfig", "Result", content);
                    this.props.addNotification(
                        "success",
                        cockpit.format(_("Config entry $0 was successfully deleted"), this.state.configDN)
                    );
                    this.props.pluginListHandler();
                    this.closeConfirmDelete();
                    this.handleCloseModal();
                })
                .fail(err => {
                    const errMsg = JSON.parse(err);
                    this.props.addNotification(
                        "error",
                        cockpit.format(_("Error during the config entry removal operation - $0"), errMsg.desc)
                    );
                    this.props.pluginListHandler();
                    this.closeConfirmDelete();
                    this.handleCloseModal();
                });
    }

    handleAddConfig() {
        this.cmdConfigOperation("add");
    }

    handleEditConfig() {
        this.cmdConfigOperation("set");
    }

    updateFields() {
        let membershipAttrList = [];

        if (this.props.rows.length > 0) {
            const pluginRow = this.props.rows.find(
                row => row.cn[0] === "referential integrity postoperation"
            );

            this.setState({
                updateDelay:
                    pluginRow["referint-update-delay"] === undefined
                        ? "0"
                        : pluginRow["referint-update-delay"][0],
                _updateDelay:
                    pluginRow["referint-update-delay"] === undefined
                        ? "0"
                        : pluginRow["referint-update-delay"][0],
                entryScope:
                    pluginRow["nsslapd-pluginentryscope"] === undefined
                        ? ""
                        : pluginRow["nsslapd-pluginentryscope"][0],
                _entryScope:
                    pluginRow["nsslapd-pluginentryscope"] === undefined
                        ? ""
                        : pluginRow["nsslapd-pluginentryscope"][0],
                excludeEntryScope:
                    pluginRow["nsslapd-pluginexcludeentryscope"] === undefined
                        ? ""
                        : pluginRow["nsslapd-pluginexcludeentryscope"][0],
                _excludeEntryScope:
                    pluginRow["nsslapd-pluginexcludeentryscope"] === undefined
                        ? ""
                        : pluginRow["nsslapd-pluginexcludeentryscope"][0],
                containerScope:
                    pluginRow["nsslapd-plugincontainerscope"] === undefined
                        ? ""
                        : pluginRow["nsslapd-plugincontainerscope"][0],
                _containerScope:
                    pluginRow["nsslapd-plugincontainerscope"] === undefined
                        ? ""
                        : pluginRow["nsslapd-plugincontainerscope"][0],
                referintConfigEntry:
                    pluginRow["nsslapd-pluginConfigArea"] === undefined
                        ? ""
                        : pluginRow["nsslapd-pluginConfigArea"][0],
                _referintConfigEntry:
                    pluginRow["nsslapd-pluginConfigArea"] === undefined
                        ? ""
                        : pluginRow["nsslapd-pluginConfigArea"][0],
                logFile:
                    pluginRow["referint-logfile"] === undefined
                        ? ""
                        : pluginRow["referint-logfile"][0],
                _logFile:
                    pluginRow["referint-logfile"] === undefined
                        ? ""
                        : pluginRow["referint-logfile"][0],
            });

            if (pluginRow["referint-membership-attr"] === undefined) {
                this.setState({
                    membershipAttr: [],
                    _membershipAttr: [],
                });
            } else {
                for (const value of pluginRow["referint-membership-attr"]) {
                    membershipAttrList = [...membershipAttrList, value];
                }
                this.setState({
                    membershipAttr: membershipAttrList,
                    _membershipAttr: [...membershipAttrList],
                });
            }
        }
    }

    render() {
        const {
            updateDelay,
            membershipAttr,
            entryScope,
            excludeEntryScope,
            containerScope,
            logFile,
            referintConfigEntry,
            configDN,
            configUpdateDelay,
            configMembershipAttr,
            configEntryScope,
            configExcludeEntryScope,
            configContainerScope,
            configEntryModalShow,
            configLogFile,
            newEntry,
            saveBtnDisabled,
            saveBtnDisabledModal,
            saving,
            savingModal,
            addSpinning,
            modalSpinning,
            error,
            errorModal,
        } = this.state;

        let saveBtnText = _("Save Config");
        let addBtnText = _("Add Config");
        const extraPrimaryProps = {};
        if (savingModal) {
            saveBtnText = _("Saving ...");
            addBtnText = _("Adding ...");
            extraPrimaryProps.spinnerAriaValueText = _("Loading");
        }

        let modalButtons = [];
        if (!newEntry) {
            modalButtons = [
                <Button
                    key="del"
                    variant="primary"
                    onClick={this.handleShowConfirmDelete}
                >
                    {_("Delete Config")}
                </Button>,
                <Button
                    key="save"
                    variant="primary"
                    onClick={this.handleEditConfig}
                    isDisabled={saveBtnDisabledModal || savingModal}
                    isLoading={savingModal}
                    spinnerAriaValueText={savingModal ? _("Saving") : undefined}
                    {...extraPrimaryProps}
                >
                    {saveBtnText}
                </Button>,
                <Button key="cancel" variant="link" onClick={this.handleCloseModal}>
                    {_("Cancel")}
                </Button>
            ];
        } else {
            modalButtons = [
                <Button
                    key="add"
                    variant="primary"
                    onClick={this.handleAddConfig}
                    isDisabled={saveBtnDisabledModal || addSpinning}
                    isLoading={addSpinning}
                    spinnerAriaValueText={addSpinning ? _("Saving") : undefined}
                    {...extraPrimaryProps}
                >
                    {addBtnText}
                </Button>,
                <Button key="cancel" variant="link" onClick={this.handleCloseModal}>
                    {_("Cancel")}
                </Button>
            ];
        }

        return (
            <div className={saving || savingModal || addSpinning || modalSpinning ? "ds-disabled" : ""}>
                <Modal
                    variant={ModalVariant.medium}
                    title={_("Manage Referential Integrity Plugin Shared Config Entry")}
                    isOpen={configEntryModalShow}
                    aria-labelledby="ds-modal"
                    onClose={this.handleCloseModal}
                    actions={modalButtons}
                >
                    <Form isHorizontal autoComplete="off">
                        <Grid className="ds-margin-top" title={_("The config entry full DN")}>
                            <GridItem span={3} className="ds-label">
                                {_("Config DN")}
                            </GridItem>
                            <GridItem span={9}>
                                <TextInput
                                    value={configDN}
                                    type="text"
                                    id="configDN"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="configDN"
                                    onChange={(e, str) => { this.handleModalChange(e) }}
                                    validated={errorModal.configDN ? ValidatedOptions.error : ValidatedOptions.default}
                                    isDisabled={!newEntry}
                                />
                                {newEntry &&
                                    <FormHelperText>
                                        {_("Value must be a valid DN")}
                                    </FormHelperText>
                                }
                            </GridItem>
                        </Grid>
                        <Grid title={_("Specifies attributes to check for and update (referint-membership-attr)")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Membership Attribute")}
                            </GridItem>
                            <GridItem span={9}>
                                <Select
                                    variant={SelectVariant.typeaheadMulti}
                                    typeAheadAriaLabel="Type an attribute"
                                    onToggle={(event, isOpen) => this.handleConfigMembershipAttrToggle(event, isOpen)}
                                    onSelect={this.handleConfigMembershipAttrSelect}
                                    onClear={this.handleConfigMembershipAttrClear}
                                    selections={configMembershipAttr}
                                    isOpen={this.state.isConfigMembershipAttrOpen}
                                    aria-labelledby="typeAhead-config-membership-attr"
                                    placeholderText={_("Type an attribute...")}
                                    noResultsFoundText={_("There are no matching entries")}
                                    validated={errorModal.configMembershipAttr ? 'error' : 'default'}
                                >
                                    {this.props.attributes.map((attr, index) => (
                                        <SelectOption
                                            key={index}
                                            value={attr}
                                        />
                                    ))}
                                </Select>
                                <FormHelperText  >
                                    {_("At least one attribute must be specified")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid title={_("Defines the subtree in which the plug-in looks for the delete or rename operations of a user entry (nsslapd-pluginEntryScope)")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Entry Scope")}
                            </GridItem>
                            <GridItem span={9}>
                                <TextInput
                                    value={configEntryScope}
                                    type="text"
                                    id="configEntryScope"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="configEntryScope"
                                    onChange={(e, str) => { this.handleModalChange(e) }}
                                    validated={errorModal.configEntryScope ? ValidatedOptions.error : ValidatedOptions.default}
                                />
                            </GridItem>
                            <FormHelperText  >
                                {_("Value must be a valid DN")}
                            </FormHelperText>
                        </Grid>
                        <Grid title={_("Defines the subtree in which the plug-in ignores any operations for deleting or renaming a user (nsslapd-pluginExcludeEntryScope)")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Exclude Entry Scope")}
                            </GridItem>
                            <GridItem span={9}>
                                <TextInput
                                    value={configExcludeEntryScope}
                                    type="text"
                                    id="configExcludeEntryScope"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="configExcludeEntryScope"
                                    onChange={(e, str) => { this.handleModalChange(e) }}
                                    validated={errorModal.configExcludeEntryScope ? ValidatedOptions.error : ValidatedOptions.default}
                                />
                                <FormHelperText  >
                                    {_("Value must be a valid DN")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid title={_("Specifies which branch the plug-in searches for the groups to which the user belongs. It only updates groups that are under the specified container branch, and leaves all other groups not updated (nsslapd-pluginContainerScope).")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Container Scope")}
                            </GridItem>
                            <GridItem span={9}>
                                <TextInput
                                    value={configContainerScope}
                                    type="text"
                                    id="configContainerScope"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="configContainerScope"
                                    onChange={(e, str) => { this.handleModalChange(e) }}
                                    validated={errorModal.configContainerScope ? ValidatedOptions.error : ValidatedOptions.default}
                                />
                                <FormHelperText  >
                                    {_("Value must be a valid DN")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid
                            title={`Specifies a path to the Referential integrity logfile. For example: /var/log/dirsrv/slapd-${
                                this.props.serverId
                            }/referint`}
                        >
                            <GridItem className="ds-label" span={3}>
                                {_("Logfile")}
                            </GridItem>
                            <GridItem span={9}>
                                <TextInput
                                    value={configLogFile}
                                    type="text"
                                    id="configLogFile"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="configLogFile"
                                    onChange={(e, str) => { this.handleModalChange(e) }}
                                    validated={errorModal.configLogFile ? ValidatedOptions.error : ValidatedOptions.default}
                                />
                                <FormHelperText>
                                    {_("Invalid log file name")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid title={_("Sets the update interval in seconds. Special values: 0 - The check is performed immediately, -1 - No check is performed. (referint-update-delay)")}>
                            <GridItem span={3} className="ds-label">
                                {_("Update Delay")}
                            </GridItem>
                            <GridItem span={9}>
                                <NumberInput
                                    value={configUpdateDelay}
                                    min={-1}
                                    max={this.maxValue}
                                    onMinus={() => { this.onMinusConfig("configUpdateDelay") }}
                                    onChange={(e) => { this.onConfigChange(e, "configUpdateDelay", -1) }}
                                    onPlus={() => { this.onPlusConfig("configUpdateDelay") }}
                                    inputName="input"
                                    inputAriaLabel="number input"
                                    minusBtnAriaLabel="minus"
                                    plusBtnAriaLabel="plus"
                                    widthChars={8}
                                />
                            </GridItem>
                        </Grid>
                    </Form>
                </Modal>

                <PluginBasicConfig
                    rows={this.props.rows}
                    serverId={this.props.serverId}
                    cn="referential integrity postoperation"
                    pluginName="Referential Integrity"
                    cmdName="referential-integrity"
                    savePluginHandler={this.props.savePluginHandler}
                    pluginListHandler={this.props.pluginListHandler}
                    addNotification={this.props.addNotification}
                    toggleLoadingHandler={this.props.toggleLoadingHandler}
                    saveBtnDisabled={this.state.saveBtnDisabled}
                >

                    <Form isHorizontal autoComplete="off">
                        <Grid title={_("Specifies attributes to check for and update (referint-membership-attr).")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Membership Attribute")}
                            </GridItem>
                            <GridItem span={8}>
                                <Select
                                    variant={SelectVariant.typeaheadMulti}
                                    typeAheadAriaLabel="Type an attribute"
                                    onToggle={(event, isOpen) => this.handleMembershipAttrToggle(event, isOpen)}
                                    onSelect={this.handleMembershipAttrSelect}
                                    onClear={this.handleMembershipAttrClear}
                                    selections={membershipAttr}
                                    isOpen={this.state.isMembershipAttrOpen}
                                    aria-labelledby="typeAhead-membership-attr"
                                    placeholderText={_("Type an attribute...")}
                                    noResultsFoundText={_("There are no matching entries")}
                                    validated={error.membershipAttr ? 'error' : 'default'}
                                >
                                    {this.props.attributes.map((attr, index) => (
                                        <SelectOption
                                            key={index}
                                            value={attr}
                                        />
                                    ))}
                                </Select>
                                <FormHelperText  >
                                    {_("At least one attribute needs to be specified")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid title={_("Defines the subtree in which the plug-in looks for the delete or rename operations of a user entry (nsslapd-pluginEntryScope)")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Entry Scope")}
                            </GridItem>
                            <GridItem span={8}>
                                <TextInput
                                    value={entryScope}
                                    type="text"
                                    id="entryScope"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="entryScope"
                                    onChange={(e, str) => { this.handleFieldChange(e) }}
                                    validated={error.entryScope ? ValidatedOptions.error : ValidatedOptions.default}
                                />
                                <FormHelperText  >
                                    {_("The value must be a valid DN")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid title={_("Defines the subtree in which the plug-in ignores any operations for deleting or renaming a user (nsslapd-pluginExcludeEntryScope)")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Exclude Entry Scope")}
                            </GridItem>
                            <GridItem span={8}>
                                <TextInput
                                    value={excludeEntryScope}
                                    type="text"
                                    id="excludeEntryScope"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="excludeEntryScope"
                                    onChange={(e, str) => { this.handleFieldChange(e) }}
                                    validated={error.excludeEntryScope ? ValidatedOptions.error : ValidatedOptions.default}
                                />
                                <FormHelperText  >
                                    {_("The value must be a valid DN")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid title={_("Specifies which branch the plug-in searches for the groups to which the user belongs. It only updates groups that are under the specified container branch, and leaves all other groups not updated (nsslapd-pluginContainerScope).")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Container Scope")}
                            </GridItem>
                            <GridItem span={8}>
                                <TextInput
                                    value={containerScope}
                                    type="text"
                                    id="containerScope"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="containerScope"
                                    onChange={(e, str) => { this.handleFieldChange(e) }}
                                    validated={error.containerScope ? ValidatedOptions.error : ValidatedOptions.default}
                                />
                                <FormHelperText  >
                                    {_("The value must be a valid DN")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid title={_("Specifies a path to the Referential integrity logfile. For example: /var/log/dirsrv/slapd-") + `${
                            this.props.serverId
                        }/referint`}
                        >
                            <GridItem className="ds-label" span={3}>
                                {_("Logfile")}
                            </GridItem>
                            <GridItem span={8}>
                                <TextInput
                                    value={logFile}
                                    type="text"
                                    id="logFile"
                                    aria-describedby="horizontal-form-name-helper"
                                    name="logFile"
                                    onChange={(e, str) => { this.handleFieldChange(e) }}
                                    validated={error.logFile ? ValidatedOptions.error : ValidatedOptions.default}
                                />
                                <FormHelperText  >
                                    {_("Invalid log name")}
                                </FormHelperText>
                            </GridItem>
                        </Grid>
                        <Grid title={_("Sets the update interval. Special values: 0 - The check is performed immediately, -1 - No check is performed (referint-update-delay)")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Update Delay")}
                            </GridItem>
                            <GridItem span={8}>
                                <NumberInput
                                    value={updateDelay}
                                    min={-1}
                                    max={this.maxValue}
                                    onMinus={() => { this.onMinusConfig("updateDelay") }}
                                    onChange={(e) => { this.onConfigChange(e, "updateDelay", 0) }}
                                    onPlus={() => { this.onPlusConfig("updateDelay") }}
                                    inputName="input"
                                    inputAriaLabel="number input"
                                    minusBtnAriaLabel="minus"
                                    plusBtnAriaLabel="plus"
                                    widthChars={8}
                                    unit="Seconds"
                                />
                            </GridItem>
                        </Grid>
                        <Grid title={_("The value to set as nsslapd-pluginConfigArea")}>
                            <GridItem className="ds-label" span={3}>
                                {_("Shared Config Entry")}
                            </GridItem>
                            {this.state.referintConfigEntry !== "" &&
                                <GridItem className="ds-right-margin" span={6}>
                                    <TextInput
                                        value={referintConfigEntry}
                                        type="text"
                                        id="referintConfigEntry"
                                        aria-describedby="horizontal-form-name-helper"
                                        name="referintConfigEntry"
                                        readOnlyVariant={'plain'}
                                    />
                                </GridItem>
                            }
                            <GridItem span={2}>
                                <Button
                                    variant="primary"
                                    onClick={this.handleOpenModal}
                                >
                                    {this.state.referintConfigEntry !== "" ? _("Manage Config") : _("Create Config")}
                                </Button>
                            </GridItem>
                        </Grid>
                    </Form>
                    <Button
                        className="ds-margin-top-lg"
                        key="at"
                        isLoading={saving}
                        spinnerAriaValueText={saving ? _("Loading") : undefined}
                        variant="primary"
                        onClick={this.handleSaveConfig}
                        {...extraPrimaryProps}
                        isDisabled={saveBtnDisabled || saving}
                    >
                        {saveBtnText}
                    </Button>
                </PluginBasicConfig>
                <DoubleConfirmModal
                    showModal={this.state.showConfirmDelete}
                    closeHandler={this.closeConfirmDelete}
                    handleChange={this.onChange}
                    actionHandler={this.deleteConfig}
                    spinning={this.state.modalSpinning}
                    item={this.state.configDN}
                    checked={this.state.modalChecked}
                    mTitle={_("Delete RI Plugin Config Entry")}
                    mMsg={_("Are you sure you want to delete this config entry?")}
                    mSpinningMsg={_("Deleting ...")}
                    mBtnName={_("Delete")}
                />
            </div>
        );
    }
}

ReferentialIntegrity.propTypes = {
    rows: PropTypes.array,
    serverId: PropTypes.string,
    savePluginHandler: PropTypes.func,
    pluginListHandler: PropTypes.func,
    addNotification: PropTypes.func,
    toggleLoadingHandler: PropTypes.func
};

ReferentialIntegrity.defaultProps = {
    rows: [],
    serverId: "",
};

export default ReferentialIntegrity;
