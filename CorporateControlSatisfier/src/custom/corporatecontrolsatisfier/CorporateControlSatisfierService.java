/*
 * Copyright (C) 2026 The halogenOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package custom.corporatecontrolsatisfier;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;

import org.json.JSONArray;

/**
 * Caller-gated provider that hands out the control-conformance attributes to
 * the processes that legitimately need them, and only those. The attributes
 * live in this app's own (RRO-overlaid) resource table, so they never enter
 * the framework-res ("android") resource table.
 */
public class CorporateControlSatisfierService extends ContentProvider {

    private static final String METHOD_OBTAIN = "obtainControlConformanceAttributes";
    private static final String KEY_ATTRIBUTES = "attributes";

    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PACKAGE_VENDING = "com.android.vending";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        if (!METHOD_OBTAIN.equals(method)) {
            return null;
        }

        final int uid = Binder.getCallingUid();
        final String[] pkgs = getContext().getPackageManager().getPackagesForUid(uid);
        if (!isAllowed(pkgs)) {
            return null;
        }

        final String[] attrs = getContext().getResources().getStringArray(
                "native".equals(arg)
                        ? R.array.control_conformance_attributes_native
                        : R.array.control_conformance_attributes);
        final Bundle result = new Bundle();
        result.putStringArray(KEY_ATTRIBUTES, attrs);
        return result;
    }

    private boolean isAllowed(String[] pkgs) {
        if (pkgs == null) {
            return false;
        }
        for (String pkg : pkgs) {
            if (PACKAGE_GMS.equals(pkg) || PACKAGE_VENDING.equals(pkg)) {
                return true;
            }
            if (isUserOptedPackage(pkg)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the user opted this package into the spoof layer through the
     * Settings UI (Settings.Secure.ATTESTATION_SPOOF_PACKAGES, JSON array).
     * The framework applies the same list when deciding which processes get
     * the spoofed properties, so the two checks stay consistent.
     */
    private boolean isUserOptedPackage(String pkg) {
        try {
            String json = Settings.Secure.getString(getContext().getContentResolver(),
                    "attestation_spoof_packages");
            if (TextUtils.isEmpty(json)) {
                return false;
            }
            JSONArray arr = new JSONArray(json);
            for (int i = 0; i < arr.length(); i++) {
                if (pkg.equals(arr.optString(i))) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }
}
