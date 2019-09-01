import {PolymerElement} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/@polymer/iron-flex-layout/iron-flex-layout-classes.js';
import '/resources/node_modules/@polymer/app-layout/app-header/app-header.js';
import '/resources/node_modules/@polymer/app-layout/app-header-layout/app-header-layout.js';
import '/resources/node_modules/@polymer/app-layout/app-scroll-effects/app-scroll-effects.js';
import '/resources/node_modules/@polymer/app-layout/app-toolbar/app-toolbar.js';
import '/resources/node_modules/@polymer/iron-pages/iron-pages.js';
import '/resources/node_modules/@polymer/paper-icon-button/paper-icon-button.js';
import '/resources/node_modules/@polymer/paper-progress/paper-progress.js';
import '/resources/node_modules/@polymer/app-route/app-location.js';
import '/resources/node_modules/@polymer/app-route/app-route.js';
import '/resources/components/volumetric-config.js';
import '/resources/components/volumetric-plugins.js';
import '/resources/components/volumetric-results.js';
import '/resources/components/volumetric-404.js';
import {html} from '/resources/node_modules/@polymer/polymer/lib/utils/html-tag.js';

/**
 * @customElement
 * @polymer
 */
class VolumetricShell extends PolymerElement {
    static get template() {
        return html`
        <style is="custom-style" include="iron-flex iron-flex-alignment">
            :host {
                display: block;
                margin: 0px;
                font-family: Sans-Serif;
            }

            paper-progress {
                width: 100%;
            }

            paper-progress.error {
                --paper-progress-active-color: var(--paper-red-500);
            }

            .status-text {
                text-align: center;
                font-size: 75%;
            }

            .edge-fade {
                width: 2px;
                height: 50%;
                margin: 0px 10px 0px 10px;
                background-repeat: no-repeat;
                background-position: 0 0;
                background-image: -webkit-gradient(linear, left top, left bottom, color-stop(0%, hsla(0, 0%, 0%, 0)), color-stop(50%, hsla(0, 0%, 0%, .4)), color-stop(100%, hsla(0, 0%, 0%, 0)));
                background-image: -webkit-linear-gradient(top, hsla(0, 0%, 0%, 0) 0%, hsla(0, 0%, 0%, .4) 50%, hsla(0, 0%, 0%, 0) 100%);
                background-image: -moz-linear-gradient(top, hsla(0, 0%, 0%, 0) 0%, hsla(0, 0%, 0%, .4) 50%, hsla(0, 0%, 0%, 0) 100%);
                background-image: -ms-linear-gradient(top, hsla(0, 0%, 0%, 0) 0%, hsla(0, 0%, 0%, .4) 50%, hsla(0, 0%, 0%, 0) 100%);
                background-image: -o-linear-gradient(top, hsla(0, 0%, 0%, 0) 0%, hsla(0, 0%, 0%, .4) 50%, hsla(0, 0%, 0%, 0) 100%);
                background-image: linear-gradient(to bottom, hsla(0, 0%, 0%, 0) 0%, hsla(0, 0%, 50%, .4) 50%, hsla(0, 0%, 0%, 0) 100%);
            }

            .text-capitalize {
                text-transform: capitalize;
            }
        </style>

        <app-location route="{{route}}"></app-location>
        <app-route route="{{route}}" pattern="[[rootPattern]]:page" data="{{routeData}}" tail="{{subroute}}"></app-route>

        <app-header slot="header" condenses="" fixed="" effects="waterfall">
            <app-toolbar>
                <paper-icon-button src="/resources/images/volatility.svg" on-tap="_returnHome"></paper-icon-button>
                <div>Volumetric</div>
                <div class="edge-fade"></div>
                <div class="text-capitalize">[[page]]</div>
                <div id="status" class="main-title flex status-text">[[status]]</div>
                <paper-icon-button class="end-justified" icon="settings"></paper-icon-button>
                <paper-progress id="progressBar" value="[[progress]]" bottom-item=""></paper-progress>
            </app-toolbar>
        </app-header>

        <iron-pages id="pages" selected="[[page]]" attr-for-selected="name" fallback-selection="404" role="main">
            <volumetric-plugins name="plugins" page="{{page}}" plugin="{{plugin}}"></volumetric-plugins>
            <volumetric-config name="config" page="{{page}}" plugin="{{plugin}}" job-id="{{jobId}}"></volumetric-config>
            <volumetric-results id="resultsPage" name="results" page="{{page}}" job-id="{{jobId}}"></volumetric-results>
            <volumetric-404 name="404"></volumetric-404>
        </iron-pages>
`;
    }

    static get is() {
        return 'volumetric-shell';
    }

    static get properties() {
        return {
            page: {
                type: String,
                reflectToAttribute: true,
                observer: '_pageChanged',
            },
            rootPattern: String,
            routeData: Object,
            subroute: String,
            status: String,
            progress: {
                value: 0,
                type: Number,
                notify: true
            }
        };
    }

    static get observers() {
        return [
            '_routePageChanged(routeData.page)',
            '_launchJob(jobId)'
        ];
    }

    constructor() {
        super();

        // Get root pattern for app-route, for more info about `rootPath` see:
        // https://www.polymer-project.org/2.0/docs/upgrade#urls-in-templates
        this.rootPattern = (new URL(this.rootPath)).pathname;
    }

    _routePageChanged(page) {
        // Polymer 2.0 will call with `undefined` on initialization.
        // Ignore until we are properly called with a string.
        if (page === undefined) {
            return;
        }

        // If no page was found in the route data, page will be an empty string.
        // Deault to 'view1' in that case.
        this.page = page || 'plugins';
    }

    _pageChanged(page) {
        // Load page import on demand. Show 404 page if fails
        // let resolvedPageUrl = this.resolveUrl('/resources/components/volumetric-' + page + '.js');
        // import(resolvedPageUrl).then(null, this._showPage404.bind(this));
        if (page == 'plugins') {
            this.status = '';
            this.$.progressBar.classList.remove("error");
            this.progress = 0;
        }
    }

    _showPage404() {
        this.page = '404';
    }

    _returnHome() {
        this.page = 'plugins';
    }

    _launchJob() {
        if (this.$.resultsPage.$ !== undefined) {
            // Reset the results page if it's been loaded.
            this.progress = 0;
            this.$.resultsPage.metadata = {'columns': {}, 'size': 20};
            this.$.resultsPage.$.displayCard.heading = "Processing...";
            this.$.resultsPage.$.grid.clearCache();
            this.$.resultsPage.clearPartialResults();
        }

        this.eventSource = new EventSource('/api/plugins/run_job?job_id=' + this.jobId);
        this.eventSource.addEventListener('progress', (e) => {
            let data = JSON.parse(e.data);
            if (this.jobId == data['job_id']) {
                data = data['data'];
                this.$.progressBar.classList.remove("error");
                this.progress = data['value'];
                this.status = data['message'];
            }
        });
        this.eventSource.addEventListener('error', (e) => {
            this.progress = 100;
            this.$.progressBar.classList.add("error");
            let data = JSON.parse(e.data);
            if (this.jobId == data['job_id']) {
                data = data['data'];
                this.status = data['message'];
                e.target.close();
            }
        });
        this.eventSource.addEventListener('warning', (e) => {
            let data = JSON.parse(e.data);
            if (this.jobId == data['job_id']) {
                data = data['data'];
                this.$.progressBar.classList.add("error");
                this.status = data['message'];
            }
        });
        this.eventSource.addEventListener('columns', (e) => {
            console.log("Partial output columns");
            let data = JSON.parse(e.data);
            if (this.jobId == data['job_id']) {
                data = data['data'];
                if (this.$.resultsPage.$ !== undefined) {
                    this.$.resultsPage.$.resultView.selected = 0;
                    this.$.resultsPage.partialColumns = data;
                }
            }
        });
        this.eventSource.addEventListener('partial-output', (e) => {
            console.log("Partial output");
            let data = JSON.parse(e.data);
            debugger;
            if (this.jobId == data['job_id']) {
                data = data['data'];
                if (this.$.resultsPage.$ !== undefined) {
                    this.$.resultsPage.$.resultView.selected = 0;
                    this.$.resultsPage.addPartialData(data);
                }
            }
        });
        this.eventSource.addEventListener('complete-output', (e) => {
            console.log("Complete output");
            e.target.close();
            this.progress = 100;
            if (this.$.resultsPage.buildGrid !== undefined) {
                // FIXME: We should check for when resultsPage has loaded
                // It's not clear why buildGrid might not exist?
                this.$.resultsPage.buildGrid();
            }
        });
    }
}

window.customElements.define(VolumetricShell.is, VolumetricShell);
