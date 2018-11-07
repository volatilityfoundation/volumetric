import {Element} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import '/resources/node_modules/@polymer/iron-pages/iron-pages.js';
import '/resources/node_modules/@polymer/iron-flex-layout/iron-flex-layout-classes.js';
import '/resources/node_modules/@polymer/paper-card/paper-card.js';
import '/resources/node_modules/@polymer/paper-checkbox/paper-checkbox.js';
import '/resources/node_modules/@polymer/paper-icon-button/paper-icon-button.js';
import '/resources/node_modules/paper-collapse-item/paper-collapse-item.js';
import '/resources/node_modules/@polymer/paper-listbox/paper-listbox.js';
import '/resources/node_modules/@vaadin/vaadin-grid/vaadin-grid.js';
import '/resources/node_modules/@vaadin/vaadin-grid/vaadin-grid-sorter.js';
import {html} from '../node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricResults extends Element {
    static get template() {
        return html`
    <style>
      :host {
          display: block;

          padding: 10px;
      }

      paper-card {
          width: 100%;
      }

      .constrained {
          width: 100%;
          overflow: auto;
      }

      .tree_indicator {
          background-color: #0d47a1;
          position: absolute;
      }
    </style>

        <iron-ajax id="getResultMetadata" url="/api/results/metadata" last-response="{{metadata}}"></iron-ajax>
        <iron-ajax id="getResultPage" url="/api/results/get?job_id=[[jobId]]"></iron-ajax>
        <iron-ajax id="getResultFiles" url="/api/results/list_files?job_id=[[jobId]]" last-response="{{filesData}}"></iron-ajax>

        <paper-card id="displayCard" heading="Processing...">
            <div class="card-content">
                <iron-pages id="resultView" selected="0">
                    <div class="constrained">
                        <table>
                            <tbody><tr>
                                <template is="dom-repeat" items="[[partialColumns]]">
                                    <th>{{getColumnName(item)}}</th>
                                </template>
                            </tr>
                            <template is="dom-repeat" items="[[partialData]]">
                                <tr>
                                    <template is="dom-repeat" items="[[item]]" as="dataval">
                                        <td>{{dataval}}</td>
                                    </template>
                                </tr>
                            </template>
                        </tbody></table>
                    </div>
                    <vaadin-grid id="grid">
                        <vaadin-grid-column width="1px">
                            <template class="header"></template>
                            <template>
                                <div style\$="width:[[getTreeIndicatorWidth(item)]]px;" class="tree_indicator">&nbsp;
                                </div>
                            </template>
                        </vaadin-grid-column>
                        <template is="dom-repeat" items="[[metadata.columns]]" as="column">
                            <vaadin-grid-column>
                                <template class="header">
                                    <vaadin-grid-sorter path="[[column.name]]">[[column.name]]</vaadin-grid-sorter>
                                </template>
                                <template>
                                    <template is="dom-if" if="[[isColumnType(column.type, 'Disassembly')]]">
                                        <paper-collapse-item header="Disassembly">
                                            [[getItem(column.name,item)]]
                                        </paper-collapse-item>
                                    </template>
                                    <template is="dom-if" if="[[isColumnType(column.type, 'bool')]]">
                                        <paper-checkbox checked="[[getItem(column.name, item)]]" disabled=""></paper-checkbox>
                                    </template>
                                    <template is="dom-if" if="[[isDefaultType(column.type)]]">
                                        [[getItem(column.name,item)]]
                                    </template>
                                </template>
                            </vaadin-grid-column>
                        </template>
                    </vaadin-grid>
                </iron-pages>

                <template is="dom-if" if="[[filesData.length]]">
                    <hr>
                    <paper-collapse-item header="Associated Files">
                        <paper-listbox>
                            <template is="dom-repeat" items="[[filesData]]" as="item">
                                <paper-item>
                                    <a href="/api/results/download_file?job_id=[[jobId]]&amp;file_id=[[item.id]]" target="_blank" border="0">
                                        {{item.name}}
                                    </a>
                                </paper-item>
                            </template>
                        </paper-listbox>
                    </paper-collapse-item>
                </template>
            </div>
            <div class="card-actions">
                <a href="/api/results/download_config?job_id=[[jobId]]" target="_blank" border="0">
                    <paper-icon-button icon="icons:restore-page"></paper-icon-button>
                </a>
                <a href="/api/results/download_results?job_id=[[jobId]]" target="_blank" border="0">
                    <paper-icon-button icon="icons:file-download"></paper-icon-button>
                </a>
            </div>
        </paper-card>
`;
    }

    static get is() {
        return 'volumetric-results';
    }

    static get properties() {
        return {
            'partialColumns': {
                type: Object,
                notify: true,
                value: []
            },
            'partialData': {
                type: Object,
                notify: true,
                value: []
            },
            'page': {
                type: String,
                notify: true
            },
            'jobId': {
                type: String,
                notify: true
            },
            'filesData': {
                type: Object,
                notify: true,
                value: []
            }
        }
    }

    getColumns(metadata) {
        return metadata.columns;
    }

    getColumnName(item) {
        return item[1];
    }

    addPartialData(data) {
        return this.push('partialData', data);
    }

    clearPartialResults() {
        this.set('partialColumns', []);
        this.set('partialData', []);
    }


    isColumnType(column_type, desired_type) {
        return column_type == desired_type;
    }

    isDefaultType(column_type) {
        if (column_type == 'Disassembly') {
            return false;
        } else if (column_type == 'bool') {
            return false;
        }
        return true;
    }

    buildGrid() {
        this.$.getResultFiles.generateRequest();
        this.$.resultView.selected = 1;
        let getResultPage = this.$.getResultPage;
        let getResultMetadata = this.$.getResultMetadata;
        let grid = this.$.grid;
        let displayCard = this.$.displayCard;

        getResultMetadata.params = {'job_id': this.jobId};
        getResultMetadata.addEventListener('response', function() {
            grid.size = getResultMetadata.lastResponse.size;
            getResultPage.generateRequest();
        }, {once: true});

        grid.size = 0;
        grid.dataProvider = function(params, callback) {
            getResultPage.addEventListener('response', function() {
                if (getResultPage.lastResponse != undefined && getResultPage.lastResponse != null) {
                    displayCard.heading = "Results";
                    callback(getResultPage.lastResponse);
                } else {
                    callback([]);
                }
            }, {once: true});

            if (params.sortOrders === undefined || params.sortOrders.length < 1) {
                getResultPage.params = {
                    'index': params.page,
                    'page_size': params.pageSize
                };
            } else {
                getResultPage.params = {
                    'index': params.page,
                    'page_size': params.pageSize,
                    'sort_property': params.sortOrders[0].path,
                    'sort_direction': params.sortOrders[0].direction
                };
            }
            if (getResultMetadata.lastResponse) {
                getResultPage.generateRequest();
            }
        };

        getResultMetadata.generateRequest();
    }

    getItem(column, item) {
        if (column !== undefined && item !== undefined && item !== null) {
            return item[column.toLowerCase()];
        }
        return null;
    }

    getTreeIndicatorWidth(item) {
        var width = Math.max(0, this.getItem('depth', item) - 1);
        return width * 10;
    }
}

window.customElements.define(VolumetricResults.is, VolumetricResults);
