import {Element} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/@polymer/iron-flex-layout/iron-flex-layout-classes.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import '/resources/node_modules/@polymer/iron-form/iron-form.js';
import '/resources/node_modules/@polymer/iron-pages/iron-pages.js';
import '/resources/node_modules/paper-collapse-item/paper-collapse-item.js';
import '/resources/node_modules/@polymer/paper-input/paper-input.js';
import '/resources/node_modules/@polymer/paper-item/paper-item.js';
import '/resources/node_modules/@polymer/paper-card/paper-card.js';
import '/resources/node_modules/@polymer/paper-button/paper-button.js';
import '/resources/node_modules/@polymer/paper-checkbox/paper-checkbox.js';
import '/resources/node_modules/@polymer/paper-header-panel/paper-header-panel.js';
import '/resources/node_modules/@polymer/paper-tabs/paper-tabs.js';
import '/resources/node_modules/@polymer/paper-input/paper-textarea.js';
import '/resources/components/volumetric-requirement-editor.js';
import '/resources/components/volumetric-requirement-string.js';
import {html} from '/resources/node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricConfig extends Element {
    static get template() {
        return html`
    <style is="custom-style" include="iron-flex iron-flex-alignment">
      :host {
          display: block;

          padding: 10px;
      }

      paper-card {
          width: 100%;
      }

      paper-tabs {
          --paper-tabs-selection-bar-color: blue;
      }
    </style>

        <iron-ajax id="getRequirements" url\$="/api/plugins/get_requirements?plugin_name=[[plugin]]" last-response="{{requirements}}"></iron-ajax>
        <iron-ajax id="getAutomagicRequirements" url="/api/automagics/get_requirements" last-response="{{automagicRequirements}}"></iron-ajax>
        <iron-ajax id="getAutomagics" url="/api/automagics/list" last-response="{{automagics}}"></iron-ajax>
        <iron-ajax id="prepareJob" url="/api/plugins/create_job" last-response="{{jobId}}"></iron-ajax>

        <paper-card>
            <div class="card-content">
                <iron-form id="runPluginForm">
                    <paper-collapse-item header="Available Automagics">
                        <template is="dom-repeat" items="{{automagics}}">
                            <paper-item>
                                <paper-checkbox name="automagic_{{item.name}}" checked="_automagicEnabled(item)" on-tap="_automagicTapped" item\$="{{item}}">
                                    {{item.name}} - {{item.description}}
                                </paper-checkbox>
                            </paper-item>
                        </template>
                    </paper-collapse-item>
                    <paper-collapse-item header="Automagic Options" opened="">
                        <iron-form id="runAutomagicForm">
                            <volumetric-requirement-editor requirements="{{automagicRequirements}}"></volumetric-requirement-editor>
                        </iron-form>
                    </paper-collapse-item>
                    <paper-tabs id="tabs" selected="{{configPage}}">
                        <paper-tab>Defined Options</paper-tab>
                        <paper-tab>Custom Options</paper-tab>
                    </paper-tabs>
                    <iron-pages selected="{{configPage}}">
                        <div class="flex">
                            <paper-collapse-item header="{{plugin}} Options" opened="">
                                <volumetric-requirement-editor requirements="{{requirements}}"></volumetric-requirement-editor>
                            </paper-collapse-item>
                        </div>
                        <div class="flex">
                            <paper-item two-line="">
                                <paper-item-body>
                                    <div class="layout horizontal">
                                        <div class="flex">Config Options</div>
                                        <input id="fileInput" type="file" hidden="" on-change="_fileUploaded" accept=".txt, .json, text/plain, application/json">
                                        <label for="fileInput">
                                            <paper-icon-button icon="file-upload">Upload</paper-icon-button>
                                        </label>
                                    </div>
                                    <paper-textarea id="configArea" value="{{_jsonifyConfig(pluginConfig.*)}}" label="JSON config" always-float-label=""></paper-textarea>
                                </paper-item-body>
                            </paper-item>
                        </div>
                    </iron-pages>
                </iron-form>
            </div>
            <div class="card-actions layout horizontal end-justified">
                <paper-button on-tap="_runPlugin">Run</paper-button>
            </div>
        </paper-card>
`;
    }

    static get is() {
        return 'volumetric-config';
    }

    static get properties() {
        return {
            'page': {
                type: String,
                observer: '_refresh',
                notify: true
            },
            'plugin': {
                type: String,
                notify: true
            },
            'jobId': {
                type: String,
                notify: true
            },
            "pluginConfig": {
                type: Object,
                notify: true,
                value: (() => {
                    return {};
                })
            },
            'automagicConfig': {
                type: Object,
                notify: true,
                value: (() => {
                    return {};
                })
            },
            'automagicEnabled': {
                type: Object,
                notify: true,
                value: (() => {
                    return [];
                })
            }
        }
    }

    _automagicTapped(e) {
        let name = e.target.id.substring(0, 10);
        this.automagics[name]['selected'] = !this.automagics[name].get('selected', false);
    }

    _automagicEnabled(item) {
        return this.automagics[item.name]['selected'];
    }

    _refresh() {
        if (this.page == 'config') {
            if (this.$.tabs.selected === undefined) {
                this.$.tabs.selected = 0;
            }
            this.$.getRequirements.generateRequest();
            this.$.getAutomagics.generateRequest();
            this.$.getAutomagicRequirements.generateRequest();
        }
    }

    _changeType(key, value) {
        let type_val = null;
        for (let item in this.automagicRequirements) {
            if (this.automagicRequirements[item]['name'] == key) {
                type_val = this.automagicRequirements[item]['type'];
            }
        }
        for (let item in this.requirements) {
            if (this.requirements[item]['name'] == key) {
                type_val = this.requirements[item]['type'];
            }
        }
        if (type_val == 'IntRequirement') {
            return Number(value);
        } else if (type_val == 'BooleanRequirement') {
            return bool(value);
        } else {
            return value;
        }
    }

    _jsonifyConfig(changed) {
        return JSON.stringify(this.pluginConfig, null, 2);
    }

    _fileUploaded() {
        let filename = this.$.fileInput.files[0];
        let reader = new FileReader();
        let customConfig = this.pluginConfig;
        reader.onload = () => {
            this.pluginConfig = JSON.parse(reader.result);
        };
        reader.readAsText(filename);
    }

    _runPlugin() {
        let form_elements = this.$.runPluginForm.serializeForm();
        let automagicEnabled = [];
        for (let key in form_elements) {
            if (key.substring(0, 11) == 'vol_plugins') {
                let index = key.substring(key.lastIndexOf('.') + 1, key.length);
                this.pluginConfig[index] = this._changeType(index, form_elements[key]);
            } else if (key.substring(0, 13) == 'vol_automagic') {
                let index = key.substring(4, key.length);
                this.automagicConfig[index] = this._changeType(index, form_elements[key]);
            } else if (key.substring(0, 10) == 'automagic_') {
                if (form_elements[key] == 'on') {
                    // This relies on the form elements being returned in the correct order
                    automagicEnabled.push(key.substring(10, key.length));
                }
            }
        }

        this.$.configArea.value = this._jsonifyConfig();
        this.$.prepareJob.params = {
            'plugin': this.plugin,
            'automagics': JSON.stringify(automagicEnabled),
            'global_config': JSON.stringify(this.automagicConfig),
            'plugin_config': JSON.stringify(this.pluginConfig)
        };
        this.$.prepareJob.generateRequest();
        this.page = 'results';
    }
}

window.customElements.define(VolumetricConfig.is, VolumetricConfig);
