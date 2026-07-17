<template>
  <q-page class="q-pa-md">
    <div class="q-mb-lg">
      <h4 class="text-h4 text-weight-bold q-ma-none">Settings</h4>
      <p class="text-body2 text-grey-6">Application configuration</p>
    </div>

    <div v-if="loadError" class="text-negative q-mb-md">
      Failed to load settings: {{ loadError }}
    </div>

    <q-tabs v-model="tab" dense align="left" class="q-mb-md" style="flex-wrap:wrap">
      <q-tab v-if="can('config_general')" name="general" icon="settings" label="General" />
      <q-tab v-if="can('config_general')" name="accounts" icon="manage_accounts" label="Accounts" />
      <q-tab v-if="can('config_general')" name="wiki" icon="menu_book" label="Wiki" />
      <q-tab v-if="can('config_general')" name="ldap" icon="account_tree" label="LDAP" />
      <q-tab v-if="can('config_general')" name="mail" icon="email" label="Mail / SMTP" />
      <q-tab v-if="can('config_encryption')" name="encryption" icon="lock" label="Encryption" />
      <q-tab v-if="can('config_backup')" name="backup" icon="backup" label="Backup" />
      <q-tab v-if="can('config_import')" name="import" icon="upload_file" label="Import Accounts" />
      <q-tab v-if="can('config_general')" name="info" icon="info" label="Information" />
    </q-tabs>

    <q-separator />

    <q-tab-panels v-model="tab" animated>
      <!-- ====== GENERAL ====== -->
      <q-tab-panel name="general">
        <div v-if="general" class="q-gutter-md" style="max-width: 640px">
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Application</div>

          <q-select
            v-model="general.sitelang"
            :options="langOpts"
            label="Language"
            outlined dense emit-value map-options
            use-input hide-selected fill-input input-debounce="0"
            @filter="filterLang"
          />

          <div>
            <div class="text-body2 text-grey-8 q-mb-sm">Theme</div>
            <div class="sp-theme-grid">
              <button
                v-for="t in themes"
                :key="t.id"
                class="sp-theme-btn"
                :class="{ 'sp-theme-btn--active': activeTheme === t.id }"
                @click="selectTheme(t.id)"
              >
                <span class="sp-theme-swatch" :style="{ background: t.swatch }" />
                <span class="sp-theme-label">{{ t.label }}</span>
                <q-icon v-if="activeTheme === t.id" name="check" size="14px" color="primary" />
              </button>
            </div>
          </div>

          <q-input v-model="general.app_url" label="Application URL" outlined dense
            hint="Public URL (e.g. https://syspass.example.com)" />

          <q-input v-model.number="general.session_timeout" label="Session Timeout (seconds)"
            type="number" outlined dense />

          <q-separator />
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Flags</div>

          <q-toggle v-model="general.https_enabled" label="Force HTTPS" />
          <q-toggle v-model="general.debug" label="Debug mode" />
          <q-toggle v-model="general.maintenance" label="Maintenance mode" />
          <q-toggle v-model="general.check_updates" label="Check for updates" />
          <q-toggle v-model="general.log_enabled" label="Event logging" />

          <q-separator />
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Proxy</div>

          <q-toggle v-model="general.proxy_enabled" label="Enable proxy" />
          <template v-if="general.proxy_enabled">
            <q-input v-model="general.proxy_server" label="Proxy server" outlined dense />
            <q-input v-model.number="general.proxy_port" label="Proxy port" type="number" outlined dense />
            <q-input v-model="general.proxy_user" label="Proxy user (optional)" outlined dense />
          </template>

          <div class="row justify-end q-mt-md">
            <q-btn color="primary" label="Save General Settings" :loading="saving.general" @click="saveGeneral" />
          </div>
        </div>
        <div v-else class="text-center q-pa-xl">
          <q-spinner-dots size="2rem" color="primary" />
        </div>
      </q-tab-panel>

      <!-- ====== MAIL ====== -->
      <q-tab-panel name="mail">
        <div v-if="mail" class="q-gutter-md" style="max-width: 640px">
          <q-toggle v-model="mail.mail_enabled" label="Enable email / SMTP" />

          <template v-if="mail.mail_enabled">
            <q-input v-model="mail.mail_server" label="SMTP Server *" outlined dense />
            <q-input v-model.number="mail.mail_port" label="SMTP Port" type="number" outlined dense />
            <q-select
              v-model="mail.mail_security"
              :options="mailSecOpts"
              label="Security"
              outlined dense
              use-input hide-selected fill-input input-debounce="0"
              @filter="filterMailSec"
            />
            <q-input v-model="mail.mail_from" label="From address *" outlined dense />
            <q-input v-model="mail.mail_recipients" label="Recipient(s)" outlined dense
              hint="Comma-separated email addresses" />

            <q-toggle v-model="mail.mail_auth_enabled" label="SMTP Authentication" />
            <template v-if="mail.mail_auth_enabled">
              <q-input v-model="mail.mail_user" label="SMTP Username" outlined dense />
              <q-input v-model="mail.mail_pass" label="SMTP Password" type="password" outlined dense />
            </template>

            <q-toggle v-model="mail.mail_requests_enabled" label="Allow users to request accounts via email" />
          </template>

          <div class="row justify-end q-mt-md">
            <q-btn color="primary" label="Save Mail Settings" :loading="saving.mail" @click="saveMail" />
          </div>
        </div>
        <div v-else class="text-center q-pa-xl">
          <q-spinner-dots size="2rem" color="primary" />
        </div>
      </q-tab-panel>

      <!-- ====== LDAP ====== -->
      <q-tab-panel name="ldap">
        <div v-if="ldap" class="q-gutter-md" style="max-width: 640px">
          <q-toggle v-model="ldap.ldap_enabled" label="Enable LDAP authentication" />

          <template v-if="ldap.ldap_enabled">
            <q-select
              v-model="ldap.ldap_server_type"
              :options="ldapTypeOpts"
              label="Server type"
              outlined dense emit-value map-options
              use-input hide-selected fill-input input-debounce="0"
              @filter="filterLdapType"
            />
            <q-input v-model="ldap.ldap_server" label="LDAP Server (host[:port])" outlined dense />
            <q-input v-model="ldap.ldap_base" label="Search Base (DN)" outlined dense
              hint="e.g. dc=example,dc=com" />
            <q-input v-model="ldap.ldap_group" label="Group filter (optional)" outlined dense />
            <q-input v-model="ldap.ldap_binduser" label="Bind DN" outlined dense
              hint="e.g. cn=readonly,dc=example,dc=com" />
            <q-input v-model="ldap.ldap_bindpass" label="Bind Password" type="password" outlined dense />
            <q-toggle v-model="ldap.ldap_tls_enabled" label="Enable TLS (StartTLS)" />
          </template>

          <div class="row justify-end q-gutter-sm q-mt-md">
            <q-btn v-if="ldap.ldap_enabled" outline color="primary" label="Test connection"
              :loading="testingLdap" :disable="!ldap.ldap_server" @click="testLdap" />
            <q-btn color="primary" label="Save LDAP Settings" :loading="saving.ldap" @click="saveLdap" />
          </div>
        </div>
        <div v-else class="text-center q-pa-xl">
          <q-spinner-dots size="2rem" color="primary" />
        </div>
      </q-tab-panel>
      <!-- ====== ENCRYPTION ====== -->
      <q-tab-panel name="encryption">
        <div v-if="encStatus" class="q-gutter-md" style="max-width: 640px">
          <!-- Status cards -->
          <div class="row q-gutter-md">
            <q-card flat bordered class="col">
              <q-card-section>
                <div class="text-caption text-grey-6">Algorithm</div>
                <div class="text-body1 text-weight-medium">{{ encStatus.algorithm }}</div>
              </q-card-section>
            </q-card>
            <q-card flat bordered class="col">
              <q-card-section>
                <div class="text-caption text-grey-6">Key source</div>
                <div class="text-body1 text-weight-medium text-capitalize">{{ encStatus.key_source }}</div>
              </q-card-section>
            </q-card>
          </div>

          <div class="row q-gutter-md">
            <q-card flat bordered class="col">
              <q-card-section>
                <div class="text-caption text-grey-6">Encrypted accounts</div>
                <div class="text-h5 text-weight-bold text-primary">{{ encStatus.encrypted_accounts }}</div>
              </q-card-section>
            </q-card>
            <q-card flat bordered class="col">
              <q-card-section>
                <div class="text-caption text-grey-6">Encrypted history rows</div>
                <div class="text-h5 text-weight-bold text-primary">{{ encStatus.encrypted_history }}</div>
              </q-card-section>
            </q-card>
          </div>

          <q-banner v-if="encStatus.using_default_key" rounded class="bg-warning text-black">
            <template v-slot:avatar>
              <q-icon name="warning" />
            </template>
            The default insecure encryption key is in use. Change it using the form below.
          </q-banner>

          <q-separator />
          <div class="text-subtitle1 text-weight-medium">Change Encryption Key</div>
          <p class="text-body2 text-grey-7">
            Re-encrypts all stored passwords with a new key. The application will also need
            <code>ENCRYPTION_KEY</code> updated in the environment before the next restart.
          </p>

          <q-input v-model="rekey.current_key" label="Current encryption key" type="password" outlined dense />
          <q-input v-model="rekey.new_key" label="New encryption key (min 16 chars)" type="password" outlined dense />
          <q-input v-model="rekey.new_key_confirm" label="Confirm new key" type="password" outlined dense />

          <q-banner rounded class="bg-negative text-white q-mt-sm">
            <template v-slot:avatar><q-icon name="error" /></template>
            This operation re-encrypts every stored password. Enable maintenance mode first
            and ensure you have a database backup before proceeding.
          </q-banner>

          <div class="row justify-end q-mt-md">
            <q-btn
              color="negative"
              icon="vpn_key"
              label="Re-encrypt All Passwords"
              :loading="rekeyLoading"
              @click="doRekey"
            />
          </div>

          <q-banner v-if="rekeyResult" rounded class="bg-positive text-white q-mt-sm">
            {{ rekeyResult }}
          </q-banner>

          <q-separator />
          <div class="text-subtitle1 text-weight-medium">Temporary Master Password</div>
          <p class="text-body2 text-grey-7">
            Generate a time-limited temporary master password for users who need to unlock their vault
            without being told the real master password.
          </p>

          <div class="row q-gutter-md">
            <q-card flat bordered class="col">
              <q-card-section>
                <div class="text-caption text-grey-6">Status</div>
                <div class="text-body1 text-weight-medium">
                  {{ tempMasterStatus?.is_active ? 'Active' : 'Inactive' }}
                </div>
                <div v-if="tempMasterStatus?.expires_at" class="text-caption text-grey-6 q-mt-xs">
                  Expires: {{ formatUnixTime(tempMasterStatus.expires_at) }}
                </div>
              </q-card-section>
            </q-card>
            <q-card flat bordered class="col">
              <q-card-section>
                <div class="text-caption text-grey-6">Attempts</div>
                <div class="text-body1 text-weight-medium">
                  {{ tempMasterStatus?.attempts ?? 0 }}/{{ tempMasterStatus?.max_attempts ?? 50 }}
                </div>
                <div class="text-caption text-grey-6 q-mt-xs">
                  Remaining: {{ tempMasterStatus?.remaining_seconds ?? 0 }}s
                </div>
              </q-card-section>
            </q-card>
          </div>

          <q-input
            v-model.number="tempMasterForm.max_time"
            label="Lifetime (seconds)"
            type="number"
            outlined
            dense
          />
          <q-toggle v-model="tempMasterForm.send_email" label="Send email to users" />
          <q-select
            v-model="tempMasterForm.group_id"
            :options="tempMasterGroupOptions"
            label="User group (optional)"
            outlined
            dense
            emit-value
            map-options
            clearable
            :disable="!tempMasterForm.send_email"
          />

          <q-banner v-if="tempMasterResult?.password" rounded class="bg-warning text-black q-mt-sm">
            <template v-slot:avatar><q-icon name="key" /></template>
            Temporary password: <strong>{{ tempMasterResult.password }}</strong>
            <span v-if="tempMasterResult.email_error"> — {{ tempMasterResult.email_error }}</span>
          </q-banner>

          <div class="row justify-end q-mt-md">
            <q-btn
              color="secondary"
              icon="key"
              label="Generate Temporary Password"
              :loading="tempMasterLoading"
              @click="createTempMasterPassword"
            />
          </div>
        </div>
        <div v-else class="text-center q-pa-xl">
          <q-spinner-dots size="2rem" color="primary" />
        </div>
      </q-tab-panel>
      <!-- ====== ACCOUNTS ====== -->
      <q-tab-panel name="accounts">
        <div v-if="accounts" class="q-gutter-md" style="max-width: 640px">
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Display</div>
          <q-input v-model.number="accounts.account_count" label="Accounts per page" type="number" outlined dense />
          <q-toggle v-model="accounts.results_as_cards" label="Show results as cards" />
          <q-toggle v-model="accounts.account_link" label="Enable account links" />
          <q-toggle v-model="accounts.global_search" label="Global search" />

          <q-separator />
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Security</div>
          <q-toggle v-model="accounts.account_full_group_access" label="Full group access to accounts" />
          <q-toggle v-model="accounts.account_pass_to_image" label="Show password as image" />
          <q-toggle v-model="accounts.demo_enabled" label="Demo mode (read-only)" />

          <q-separator />
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Password Expiry</div>
          <q-toggle v-model="accounts.account_expire_enabled" label="Enable password expiry" />
          <template v-if="accounts.account_expire_enabled">
            <q-input v-model.number="accounts.account_expire_time" label="Expiry time (seconds)" type="number" outlined dense
              hint="Default: 10368000 = 120 days" />
          </template>

          <q-separator />
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Files</div>
          <q-toggle v-model="accounts.files_enabled" label="Enable file attachments" />
          <template v-if="accounts.files_enabled">
            <q-input v-model.number="accounts.files_allowed_size" label="Max file size (KB)" type="number" outlined dense />
            <q-input v-model="accounts.files_allowed_exts" label="Allowed extensions (comma-separated)" outlined dense
              hint="Leave empty to allow all. e.g. pdf,docx,png" />
          </template>

          <q-separator />
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Public Links</div>
          <q-toggle v-model="accounts.publinks_enabled" label="Enable public links" />
          <template v-if="accounts.publinks_enabled">
            <q-toggle v-model="accounts.publinks_image_enabled" label="Show password as image in public link" />
            <q-input v-model.number="accounts.publinks_max_time" label="Max link lifetime (seconds)" type="number" outlined dense />
            <q-input v-model.number="accounts.publinks_max_views" label="Max link views" type="number" outlined dense />
          </template>

          <div class="row justify-end q-mt-md">
            <q-btn color="primary" label="Save Account Settings" :loading="saving.accounts" @click="saveAccounts" />
          </div>
        </div>
        <div v-else class="text-center q-pa-xl"><q-spinner-dots size="2rem" color="primary" /></div>
      </q-tab-panel>

      <!-- ====== WIKI ====== -->
      <q-tab-panel name="wiki">
        <div v-if="wiki" class="q-gutter-md" style="max-width: 640px">
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Generic Wiki</div>
          <q-toggle v-model="wiki.wiki_enabled" label="Enable wiki integration" />
          <template v-if="wiki.wiki_enabled">
            <q-input v-model="wiki.wiki_pageurl" label="Wiki page URL" outlined dense
              hint="URL template, use %ACCOUNT% as placeholder" />
            <q-input v-model="wiki.wiki_searchurl" label="Wiki search URL" outlined dense />
            <q-input v-model="wiki.wiki_filter" label="Wiki filter" outlined dense />
          </template>

          <q-separator />
          <div class="text-subtitle1 text-weight-medium q-mb-sm">DokuWiki</div>
          <q-toggle v-model="wiki.dokuwiki_enabled" label="Enable DokuWiki integration" />
          <template v-if="wiki.dokuwiki_enabled">
            <q-input v-model="wiki.dokuwiki_url" label="DokuWiki URL" outlined dense />
            <q-input v-model="wiki.dokuwiki_url_base" label="DokuWiki base URL" outlined dense />
            <q-input v-model="wiki.dokuwiki_namespace" label="Namespace" outlined dense />
            <q-input v-model="wiki.dokuwiki_user" label="Username" outlined dense />
            <q-input v-model="wiki.dokuwiki_pass" label="Password" type="password" outlined dense />
          </template>

          <div class="row justify-end q-mt-md">
            <q-btn color="primary" label="Save Wiki Settings" :loading="saving.wiki" @click="saveWiki" />
          </div>
        </div>
        <div v-else class="text-center q-pa-xl"><q-spinner-dots size="2rem" color="primary" /></div>
      </q-tab-panel>

      <!-- ====== BACKUP ====== -->
      <q-tab-panel name="backup">
        <div class="q-gutter-md" style="max-width: 640px">
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Export / Backup</div>
          <p class="text-body2 text-grey-7">
            Use encrypted KDBX for a portable KeePass database. KeePass XML is
            available only as a plaintext interoperability format.
          </p>

          <q-banner rounded class="bg-warning text-black q-mb-md">
            <template v-slot:avatar><q-icon name="warning" /></template>
            CSV and KeePass XML exports contain plaintext passwords. Protect them accordingly.
          </q-banner>

          <div class="row q-gutter-md">
            <q-btn color="positive" icon="enhanced_encryption" label="Export encrypted KDBX" :loading="exporting.kdbx" @click="kdbxDialog = true" />
            <q-btn color="primary" icon="download" label="Export as XML" :loading="exporting.xml" @click="doExport('xml')" />
            <q-btn color="secondary" icon="download" label="Export as CSV" :loading="exporting.csv" @click="doExport('csv')" />
            <q-btn flat color="accent" icon="download" label="KeePass XML (plaintext)" :loading="exporting.keepass" @click="doExport('keepass')" />
          </div>

          <q-dialog v-model="kdbxDialog" persistent>
            <q-card style="min-width: 420px; max-width: 92vw">
              <q-card-section>
                <div class="text-h6">Protect KeePass export</div>
                <div class="text-body2 text-grey-7 q-mt-xs">
                  Choose a new password for the exported KDBX file. Do not reuse your sysPass master password.
                </div>
              </q-card-section>
              <q-card-section class="q-gutter-md">
                <q-input
                  v-model="kdbxForm.password"
                  :type="showKdbxPassword ? 'text' : 'password'"
                  label="Export password"
                  outlined
                  autofocus
                  hint="At least 12 characters"
                  counter
                  :error="Boolean(kdbxForm.password) && kdbxForm.password.length < 12"
                  error-message="Password must be at least 12 characters"
                >
                  <template v-slot:append>
                    <q-icon :name="showKdbxPassword ? 'visibility_off' : 'visibility'" class="cursor-pointer" @click="showKdbxPassword = !showKdbxPassword" />
                  </template>
                </q-input>
                <q-input
                  v-model="kdbxForm.confirm"
                  :type="showKdbxPassword ? 'text' : 'password'"
                  label="Confirm export password"
                  outlined
                  :error="Boolean(kdbxForm.confirm) && kdbxForm.password !== kdbxForm.confirm"
                  error-message="Passwords do not match"
                  @keyup.enter="doKdbxExport"
                />
              </q-card-section>
              <q-card-actions align="right">
                <q-btn flat label="Cancel" @click="closeKdbxDialog" />
                <q-btn
                  color="positive"
                  icon="download"
                  label="Create KDBX"
                  :loading="exporting.kdbx"
                  :disable="kdbxForm.password.length < 12 || kdbxForm.password !== kdbxForm.confirm"
                  @click="doKdbxExport"
                />
              </q-card-actions>
            </q-card>
          </q-dialog>
        </div>
      </q-tab-panel>

      <!-- ====== IMPORT ACCOUNTS ====== -->
      <q-tab-panel name="import">
        <div class="q-gutter-md" style="max-width: 640px">
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Import Accounts</div>

          <q-select
            v-model="importFormat"
            :options="['csv', 'xml', 'keepass']"
            label="Import format"
            outlined dense
          />

          <q-file
            v-model="importFile"
            :label="`Select ${importFormat.toUpperCase()} file`"
            outlined dense
            :accept="importFormat === 'csv' ? '.csv' : '.xml'"
          >
            <template v-slot:prepend><q-icon name="attach_file" /></template>
          </q-file>

          <template v-if="importFormat === 'csv'">
            <q-input v-model="csvDelimiter" label="CSV delimiter" outlined dense maxlength="1" style="max-width:120px" />
          </template>

          <div class="row justify-end q-mt-md">
            <q-btn color="primary" icon="upload" label="Import" :loading="importing" @click="doImport" :disable="!importFile" />
          </div>

          <div v-if="importResult" class="q-mt-md">
            <q-banner rounded :class="importResult.errors?.length ? 'bg-warning text-black' : 'bg-positive text-white'">
              <div>Imported: {{ importResult.stats?.accounts_imported ?? 0 }} accounts</div>
              <div v-if="importResult.errors?.length">
                Errors ({{ importResult.errors.length }}):
                <ul>
                  <li v-for="(e, i) in importResult.errors" :key="i">{{ e }}</li>
                </ul>
              </div>
            </q-banner>
          </div>
        </div>
      </q-tab-panel>

      <!-- ====== INFORMATION ====== -->
      <q-tab-panel name="info">
        <div v-if="sysInfo" class="q-gutter-md" style="max-width: 640px">
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Application</div>
          <q-list bordered separator rounded>
            <q-item>
              <q-item-section><q-item-label caption>App Version</q-item-label><q-item-label>{{ sysInfo.app_version }}</q-item-label></q-item-section>
            </q-item>
            <q-item v-if="sysInfo.config_version">
              <q-item-section><q-item-label caption>Config Version</q-item-label><q-item-label>{{ sysInfo.config_version }}</q-item-label></q-item-section>
            </q-item>
            <q-item v-if="sysInfo.db_version">
              <q-item-section><q-item-label caption>DB Schema Version</q-item-label><q-item-label>{{ sysInfo.db_version }}</q-item-label></q-item-section>
            </q-item>
            <q-item v-if="sysInfo.db_host">
              <q-item-section><q-item-label caption>Database Host</q-item-label><q-item-label>{{ sysInfo.db_host }}</q-item-label></q-item-section>
            </q-item>
            <q-item v-if="sysInfo.db_name">
              <q-item-section><q-item-label caption>Database Name</q-item-label><q-item-label>{{ sysInfo.db_name }}</q-item-label></q-item-section>
            </q-item>
          </q-list>

          <div class="text-subtitle1 text-weight-medium q-mt-md q-mb-sm">Database Statistics</div>
          <div class="row q-gutter-md">
            <q-card flat bordered class="col">
              <q-card-section class="text-center">
                <div class="text-h4 text-weight-bold text-primary">{{ sysInfo.account_count }}</div>
                <div class="text-caption text-grey-6">Accounts</div>
              </q-card-section>
            </q-card>
            <q-card flat bordered class="col">
              <q-card-section class="text-center">
                <div class="text-h4 text-weight-bold text-primary">{{ sysInfo.user_count }}</div>
                <div class="text-caption text-grey-6">Users</div>
              </q-card-section>
            </q-card>
            <q-card flat bordered class="col">
              <q-card-section class="text-center">
                <div class="text-h4 text-weight-bold text-primary">{{ sysInfo.category_count }}</div>
                <div class="text-caption text-grey-6">Categories</div>
              </q-card-section>
            </q-card>
            <q-card flat bordered class="col">
              <q-card-section class="text-center">
                <div class="text-h4 text-weight-bold text-primary">{{ sysInfo.client_count }}</div>
                <div class="text-caption text-grey-6">Clients</div>
              </q-card-section>
            </q-card>
            <q-card flat bordered class="col">
              <q-card-section class="text-center">
                <div class="text-h4 text-weight-bold text-primary">{{ sysInfo.tag_count }}</div>
                <div class="text-caption text-grey-6">Tags</div>
              </q-card-section>
            </q-card>
          </div>
        </div>
        <div v-else class="text-center q-pa-xl"><q-spinner-dots size="2rem" color="primary" /></div>
      </q-tab-panel>
    </q-tab-panels>
  </q-page>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { Notify } from 'quasar'
import api from '@/api/axios'
import { themes, applyTheme, getSavedTheme } from '@/composables/useTheme'
import { useMainStore } from '@/stores'

const store = useMainStore()
const can = (key) => store.hasPermission(key)

const TAB_PERMS = [
  ['general', 'config_general'],
  ['accounts', 'config_general'],
  ['wiki', 'config_general'],
  ['ldap', 'config_general'],
  ['mail', 'config_general'],
  ['encryption', 'config_encryption'],
  ['backup', 'config_backup'],
  ['import', 'config_import'],
  ['info', 'config_general'],
]
const firstAccessibleTab = TAB_PERMS.find(([, perm]) => can(perm))?.[0] ?? 'general'
const tab = ref(firstAccessibleTab)
const loadError = ref(null)

const general = ref(null)
const mail = ref(null)
const ldap = ref(null)
const accounts = ref(null)
const wiki = ref(null)
const encStatus = ref(null)
const sysInfo = ref(null)
const saving = ref({ general: false, mail: false, ldap: false, accounts: false, wiki: false })
const testingLdap = ref(false)
const rekey = ref({ current_key: '', new_key: '', new_key_confirm: '' })
const rekeyLoading = ref(false)
const rekeyResult = ref(null)
const tempMasterStatus = ref(null)
const tempMasterResult = ref(null)
const tempMasterLoading = ref(false)
const tempMasterForm = ref({ max_time: 3600, send_email: false, group_id: null })
const tempMasterGroupOptions = ref([{ label: 'All users', value: null }])
const activeTheme = ref(getSavedTheme())

// Backup / export
const exporting = ref({ xml: false, csv: false, keepass: false, kdbx: false })
const kdbxDialog = ref(false)
const showKdbxPassword = ref(false)
const kdbxForm = ref({ password: '', confirm: '' })

// Import
const importFormat = ref('csv')
const importFile = ref(null)
const csvDelimiter = ref(',')
const importing = ref(false)
const importResult = ref(null)

function selectTheme(id) {
  activeTheme.value = id
  applyTheme(id)
  if (general.value) general.value.sitetheme = id
}

const langOptions = [
  { label: 'English (US)', value: 'en_US' },
  { label: 'Spanish (ES)', value: 'es_ES' },
  { label: 'French (FR)', value: 'fr_FR' },
  { label: 'German (DE)', value: 'de_DE' },
  { label: 'Portuguese (BR)', value: 'pt_BR' },
  { label: 'Italian (IT)', value: 'it_IT' },
  { label: 'Russian (RU)', value: 'ru_RU' },
  { label: 'Japanese (JP)', value: 'ja_JP' },
  { label: 'Polish (PL)', value: 'pl_PL' },
  { label: 'Dutch (NL)', value: 'nl_NL' },
  { label: 'Catalan (ES)', value: 'ca_ES' },
]
const ldapTypeOptions = [
  { label: 'Standard LDAP', value: 1 },
  { label: 'Active Directory', value: 2 },
]
const mailSecOptions = ['none', 'ssl', 'tls']

// Filtered refs (initialised to full lists)
const langOpts = ref([...langOptions])
const ldapTypeOpts = ref([...ldapTypeOptions])
const mailSecOpts = ref([...mailSecOptions])

function filterLang(val, update) {
  update(() => {
    langOpts.value = val
      ? langOptions.filter(o => o.label.toLowerCase().includes(val.toLowerCase()))
      : [...langOptions]
  })
}
function filterLdapType(val, update) {
  update(() => {
    ldapTypeOpts.value = val
      ? ldapTypeOptions.filter(o => o.label.toLowerCase().includes(val.toLowerCase()))
      : [...ldapTypeOptions]
  })
}
function filterMailSec(val, update) {
  update(() => {
    mailSecOpts.value = val
      ? mailSecOptions.filter(o => o.includes(val.toLowerCase()))
      : [...mailSecOptions]
  })
}

async function load() {
  loadError.value = null
  try {
    const [settingsRes, encRes, infoRes, tempMasterRes, groupsRes] = await Promise.all([
      api.get('/settings'),
      api.get('/settings/encryption'),
      api.get('/settings/info'),
      api.get('/settings/encryption/temp-master').catch(() => ({ data: null })),
      api.get('/user-groups').catch(() => ({ data: [] })),
    ])
    general.value = settingsRes.data.general
    mail.value = settingsRes.data.mail
    ldap.value = settingsRes.data.ldap
    accounts.value = settingsRes.data.accounts
    wiki.value = settingsRes.data.wiki
    encStatus.value = encRes.data
    sysInfo.value = infoRes.data
    tempMasterStatus.value = tempMasterRes.data || {
      is_active: false,
      created_at: null,
      expires_at: null,
      attempts: 0,
      max_attempts: 50,
      remaining_seconds: 0,
    }
    tempMasterGroupOptions.value = [
      { label: 'All users', value: null },
      ...groupsRes.data.map(group => ({ label: group.name, value: group.id })),
    ]
    if (general.value?.sitetheme) {
      activeTheme.value = general.value.sitetheme
      applyTheme(general.value.sitetheme)
    }
  } catch (e) {
    loadError.value = e.response?.data?.detail || e.message
  }
}

async function doRekey() {
  rekeyResult.value = null
  rekeyLoading.value = true
  try {
    const r = await api.post('/settings/encryption/rekey', rekey.value)
    rekeyResult.value = `${r.data.message} — ${r.data.accounts_rekeyed} accounts, ${r.data.history_rekeyed} history rows re-encrypted. ${r.data.warning}`
    rekey.value = { current_key: '', new_key: '', new_key_confirm: '' }
    // Refresh status
    const enc = await api.get('/settings/encryption')
    encStatus.value = enc.data
    Notify.create({ message: 'Re-key completed successfully', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Re-key failed', color: 'negative' })
  } finally {
    rekeyLoading.value = false
  }
}

function formatUnixTime(value) {
  if (!value) return 'Never'
  return new Date(value * 1000).toLocaleString()
}

async function createTempMasterPassword() {
  tempMasterLoading.value = true
  tempMasterResult.value = null
  try {
    const r = await api.post('/settings/encryption/temp-master', tempMasterForm.value)
    tempMasterResult.value = r.data
    tempMasterStatus.value = r.data
    Notify.create({
      message: r.data.emailed_to
        ? `Temporary password generated and emailed to ${r.data.emailed_to} user(s)`
        : 'Temporary password generated',
      color: r.data.email_error ? 'warning' : 'positive',
    })
  } catch (e) {
    Notify.create({
      message: e.response?.data?.detail?.message || e.response?.data?.detail || 'Failed to generate temporary password',
      color: 'negative',
    })
  } finally {
    tempMasterLoading.value = false
  }
}

async function saveGeneral() {
  saving.value.general = true
  try {
    const r = await api.put('/settings/general', general.value)
    general.value = r.data
    Notify.create({ message: 'General settings saved', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    saving.value.general = false
  }
}

async function saveMail() {
  saving.value.mail = true
  try {
    const r = await api.put('/settings/mail', mail.value)
    mail.value = r.data
    Notify.create({ message: 'Mail settings saved', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    saving.value.mail = false
  }
}

async function testLdap() {
  testingLdap.value = true
  try {
    const r = await api.post('/ldap/test-connection', {
      ldap_uri: ldap.value.ldap_server,
      base_dn: ldap.value.ldap_base || '',
      bind_dn: ldap.value.ldap_binduser || null,
      bind_password: ldap.value.ldap_bindpass || null,
      use_tls: !!ldap.value.ldap_tls_enabled,
    })
    if (r.data?.success)
      Notify.create({ message: r.data.detail || 'Connection successful', color: 'positive' })
    else
      Notify.create({ message: r.data?.detail || 'LDAP connection failed', color: 'negative' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'LDAP connection failed', color: 'negative' })
  } finally {
    testingLdap.value = false
  }
}

async function saveLdap() {
  saving.value.ldap = true
  try {
    const r = await api.put('/settings/ldap', ldap.value)
    ldap.value = r.data
    Notify.create({ message: 'LDAP settings saved', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    saving.value.ldap = false
  }
}

async function saveAccounts() {
  saving.value.accounts = true
  try {
    const r = await api.put('/settings/accounts', accounts.value)
    accounts.value = r.data
    Notify.create({ message: 'Account settings saved', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    saving.value.accounts = false
  }
}

async function saveWiki() {
  saving.value.wiki = true
  try {
    const r = await api.put('/settings/wiki', wiki.value)
    wiki.value = r.data
    Notify.create({ message: 'Wiki settings saved', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    saving.value.wiki = false
  }
}

async function doExport(format) {
  exporting.value[format] = true
  try {
    const r = await api.get(`/import-export/export/${format}`)
    const mimeTypes = { csv: 'text/csv;charset=utf-8', xml: 'application/xml', keepass: 'application/xml' }
    const blob = new Blob([r.data.content], { type: mimeTypes[format] || 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = r.data.filename
    a.click()
    URL.revokeObjectURL(url)
    Notify.create({ message: `Export as ${format.toUpperCase()} started`, color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Export failed', color: 'negative' })
  } finally {
    exporting.value[format] = false
  }
}

function closeKdbxDialog() {
  kdbxDialog.value = false
  showKdbxPassword.value = false
  kdbxForm.value = { password: '', confirm: '' }
}

async function doKdbxExport() {
  if (kdbxForm.value.password.length < 12 || kdbxForm.value.password !== kdbxForm.value.confirm) return
  exporting.value.kdbx = true
  try {
    const response = await api.post('/import-export/export/keepass/kdbx', {
      export_password: kdbxForm.value.password,
      export_password_confirm: kdbxForm.value.confirm,
    }, { responseType: 'blob' })
    const url = URL.createObjectURL(response.data)
    const link = document.createElement('a')
    link.href = url
    link.download = 'pysyspass_export.kdbx'
    link.click()
    URL.revokeObjectURL(url)
    closeKdbxDialog()
    Notify.create({ message: 'Encrypted KeePass database created', color: 'positive' })
  } catch (e) {
    Notify.create({ message: 'KDBX export failed', color: 'negative' })
  } finally {
    exporting.value.kdbx = false
  }
}

async function doImport() {
  if (!importFile.value) return
  importing.value = true
  importResult.value = null
  try {
    const form = new FormData()
    form.append('file', importFile.value)
    form.append('user_id', '1')
    if (importFormat.value === 'csv') form.append('delimiter', csvDelimiter.value)
    const r = await api.post(`/import-export/import/${importFormat.value}`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    importResult.value = r.data
    Notify.create({ message: 'Import completed', color: importResult.value.errors?.length ? 'warning' : 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Import failed', color: 'negative' })
  } finally {
    importing.value = false
  }
}

onMounted(load)
</script>

<style lang="scss" scoped>
.sp-theme-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.sp-theme-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border: 1.5px solid #e5e7eb;
  border-radius: 8px;
  background: #fff;
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  color: #374151;
  transition: border-color .15s, box-shadow .15s;

  &:hover {
    border-color: #9ca3af;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
  }

  &--active {
    border-color: var(--q-primary, #1976d2);
    box-shadow: 0 0 0 2px rgba(25, 118, 210, .15);
  }
}

.body--dark .sp-theme-btn {
  background: #1e293b;
  border-color: #334155;
  color: #e2e8f0;

  &:hover { border-color: #64748b; }
  &--active { border-color: var(--q-primary, #5c9dff); }
}

.sp-theme-swatch {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  flex-shrink: 0;
  box-shadow: inset 0 1px 2px rgba(0,0,0,.2);
}
</style>
