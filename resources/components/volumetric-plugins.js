/*
 * This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
 * which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
 *
 */
import {PolymerElement} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/paper-collapse-item/paper-collapse-group.js';
import '/resources/node_modules/paper-collapse-item/paper-collapse-item.js';
import '/resources/node_modules/@polymer/paper-listbox/paper-listbox.js';
import '/resources/node_modules/@polymer/paper-item/paper-item.js';
import '/resources/node_modules/@polymer/paper-card/paper-card.js';
import '/resources/node_modules/@polymer/paper-input/paper-input.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import {html} from '../node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricPlugins extends PolymerElement {
    static get template() {
        return html`
    <style>
      :host {
          display: block;

          padding: 10px;
      }

      paper-collapse-item {
          text-transform: capitalize;
      }

      paper-card {
          width: 100%;
      }
    </style>

        <iron-ajax id="listPlugins" url="/api/plugins/list" last-response="{{items}}" auto=""></iron-ajax>


        <paper-card heading="Available Plugins">
            <paper-item>
                <paper-input label="Filter" value="{{list_filter}}"></paper-input>
            </paper-item>
            <paper-listbox>
                <paper-collapse-group>
                <template is="dom-repeat" items="[[_top_level(items)]]" filter="{{_top_level_filter(list_filter, items)}}">
                    <paper-collapse-item header="[[item]]">
                        <paper-listbox>
                            <template is="dom-repeat" items="[[_subitems(items, item)]]" filter="{{_plugin_filter(list_filter)}}" as="subitem">
                                <paper-item value="{{_plugin_name(subitem)}}" on-tap="_select_plugin">
                                    <paper-item-body two-line="">
                                        <div>{{_friendly_name(subitem)}}</div>
                                        <div secondary="">{{_description(subitem)}}</div>
                                    </paper-item-body>
                                </paper-item>
                            </template>
                        </paper-listbox>
                    </paper-collapse-item>
                </template>
                </paper-collapse-group>
            </paper-listbox>
        </paper-card>
`;
    }

    static get is() {
        return 'volumetric-plugins';
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
            'list_filter': {
                type: String,
                notify: true
            }
        }
    }

    _description(item) {
        return item[1];
    }

    _friendly_name(item) {
        return item[0].substring(item[0].lastIndexOf(".") + 1, item[0].length);
    }

    _subitems(items, item) {
        let result = [];
        for (let i = 0; i < items.length; i++) {
            if (items[i][0].substring(0, item.length) === item) {
                result.push(items[i]);
            }
        }
        return result;
    }

    _refresh() {
        if (this.page == 'plugins') {
            this.$.listPlugins.generateRequest();
        }
    }

    _plugin_name(pair) {
        return pair[0];
    }

    _plugin_filter(list_filter) {
        return function(pair) {
            let result = false;
            if (pair[0] !== null)
                result = result || pair[0].includes(list_filter);
            if (pair[1] !== null)
                result = result || pair[1].includes(list_filter);
            return result;
        }
    }

    _top_level_filter(list_filter, items) {
        let filt_func = this._plugin_filter(list_filter);
        return function(item) {
            let result = false;
            for (let i = 0; i < items.length; i++) {
                if (items[i][0].substring(0, items[i][0].indexOf(".")) == item) {
                    result = result || filt_func(items[i]);
                }
            }
            return result;
        }
    }

    _select_plugin(e) {
        var element = e.target;
        while (element.value === undefined) {
            element = element.parentElement;
        }
        this.plugin = element.value;
        this.page = 'config';
        console.log("Plugin selected: " + this.plugin);
    }

    _toggle_info(e) {
        let collapseElem = this.shadowRoot.querySelector('#collapse' + e.currentTarget.dataset.index);
        collapseElem.toggle();
    }

    _top_level(items) {
        items.sort();
        let result = [];
        if (items !== null) {
            for (let i = 0; i < items.length; i++) {
                let top_level = items[i][0].substring(0, items[i][0].indexOf("."));
                if (result[result.length - 1] != top_level) {
                    result.push(top_level);
                }
            }
        }
        return result;
    }
}

window.customElements.define(VolumetricPlugins.is, VolumetricPlugins);
