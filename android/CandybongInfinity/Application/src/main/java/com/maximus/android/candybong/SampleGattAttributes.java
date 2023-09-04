/*
 * Copyright (C) 2013 The Android Open Source Project
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

package com.maximus.android.candybong;

import java.util.HashMap;

/**
 * This class includes a small subset of standard GATT attributes for demonstration purposes.
 */
public class SampleGattAttributes {
    private static final HashMap<String, String> attributes = new HashMap();
    public static String HEART_RATE_MEASUREMENT = "00002a37-0000-1000-8000-00805f9b34fb";
    public static String CLIENT_CHARACTERISTIC_CONFIG = "00002902-0000-1000-8000-00805f9b34fb";
    public static final String CHARACTERISTIC_LIGHT_STICK_1010_COMMAND_ENDPOINT = "Light Stick 1010 Command Endpoint";
    public static final String CHARACTERISTIC_LIGHT_STICK_1010_DATA_ENDPOINT = "Light Stick 1010 Data Endpoint";
    public static final String CHARACTERISTIC_LIGHT_STICK_1010_RESPONSE_ENDPOINT = "Light Stick 1010 Response Endpoint";
    public static final String CHARACTERISTIC_LIGHT_STICK_1020_COMMAND_ENDPOINT = "Light Stick 1020 Command Endpoint";
    public static final String CHARACTERISTIC_LIGHT_STICK_1020_DATA_ENDPOINT = "Light Stick 1020 Data Endpoint";
    public static final String CHARACTERISTIC_LIGHT_STICK_1020_RESPONSE_ENDPOINT = "Light Stick 1020 Response Endpoint";
    public static final String CHARACTERISTIC_LIGHT_STICK_NORDIC_COMMAND_ENDPOINT = "Light Stick Band Command Endpoint";
    public static final String CHARACTERISTIC_LIGHT_STICK_NORDIC_DATA_ENDPOINT = "Light Stick Band Data Endpoint";
    public static final String CHARACTERISTIC_LIGHT_STICK_NORDIC_RESPONSE_ENDPOINT = "Light Stick Band Response Endpoint";
    public static final String CHARACTERISTIC_CSR_GAIA_1010_COMMAND_ENDPOINT = "CSR GAIA 1010 Command Endpoint";
    public static final String CHARACTERISTIC_CSR_GAIA_1010_DATA_ENDPOINT = "CSR GAIA 1010 Data Endpoint";
    public static final String CHARACTERISTIC_CSR_GAIA_1010_RESPONSE_ENDPOINT = "CSR GAIA 1010 Response Endpoint";
    public static final String CHARACTERISTIC_CSR_GAIA_1020_COMMAND_ENDPOINT = "CSR GAIA 1020 Command Endpoint";
    public static final String CHARACTERISTIC_CSR_GAIA_1020_DATA_ENDPOINT = "CSR GAIA 1020 Data Endpoint";
    public static final String CHARACTERISTIC_CSR_GAIA_1020_RESPONSE_ENDPOINT = "CSR GAIA 1020 Response Endpoint";

    public static final String SERVICE_LIGHT_STICK_NORDIC_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
    public static final String CHARACTERISTIC_LIGHT_STICK_NORDIC_COMMAND_ENDPOINT_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
    public static final String CHARACTERISTIC_LIGHT_STICK_NORDIC_RESPONSE_ENDPOINT_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";
    static {
        // Sample Services.
        attributes.put("0000180d-0000-1000-8000-00805f9b34fb", "Heart Rate Service");
        attributes.put("0000180a-0000-1000-8000-00805f9b34fb", "Device Information Service");
        // Sample Characteristics.
        attributes.put(HEART_RATE_MEASUREMENT, "Heart Rate Measurement");
        attributes.put("00002a29-0000-1000-8000-00805f9b34fb", "Manufacturer Name String");

        attributes.put("00001101-d102-11e1-9b23-00025b00a5a5", CHARACTERISTIC_CSR_GAIA_1020_COMMAND_ENDPOINT);
        attributes.put("00001102-d102-11e1-9b23-00025b00a5a5", CHARACTERISTIC_CSR_GAIA_1020_RESPONSE_ENDPOINT);
        attributes.put("00001103-d102-11e1-9b23-00025b00a5a5", CHARACTERISTIC_CSR_GAIA_1020_DATA_ENDPOINT);
        attributes.put("00005501-d102-11e1-9b23-00025b00a5a5", CHARACTERISTIC_CSR_GAIA_1010_COMMAND_ENDPOINT);
        attributes.put("00005502-d102-11e1-9b23-00025b00a5a5", CHARACTERISTIC_CSR_GAIA_1010_RESPONSE_ENDPOINT);
        attributes.put("00005503-d102-11e1-9b23-00025b00a5a5", CHARACTERISTIC_CSR_GAIA_1010_DATA_ENDPOINT);
        attributes.put("00008701-0000-0000-0000-000000000000", "Light Stick 1020 Service");
        attributes.put("000092a4-0000-1000-8000-00805f9b34fb", CHARACTERISTIC_LIGHT_STICK_1020_COMMAND_ENDPOINT);
        attributes.put("000092a5-0000-1000-8000-00805f9b34fb", CHARACTERISTIC_LIGHT_STICK_1020_RESPONSE_ENDPOINT);
        attributes.put("000092a6-0000-1000-8000-00805f9b34fb", CHARACTERISTIC_LIGHT_STICK_1020_DATA_ENDPOINT);
        attributes.put("87011111-ffcc-2222-0000-000000008888", "Light Stick 1010 Service");
        attributes.put("000092a4-0000-1000-8000-00805f9b34fb", CHARACTERISTIC_LIGHT_STICK_1010_COMMAND_ENDPOINT);
        attributes.put("000092a5-0000-1000-8000-00805f9b34fb", CHARACTERISTIC_LIGHT_STICK_1010_RESPONSE_ENDPOINT);
        attributes.put("00008701-ffcc-2222-0000-000000008888", CHARACTERISTIC_LIGHT_STICK_1010_DATA_ENDPOINT);
        attributes.put(SERVICE_LIGHT_STICK_NORDIC_UUID, "Light Stick Nordic Service");
        attributes.put(CHARACTERISTIC_LIGHT_STICK_NORDIC_COMMAND_ENDPOINT_UUID, CHARACTERISTIC_LIGHT_STICK_NORDIC_COMMAND_ENDPOINT);
        attributes.put(CHARACTERISTIC_LIGHT_STICK_NORDIC_RESPONSE_ENDPOINT_UUID, CHARACTERISTIC_LIGHT_STICK_NORDIC_RESPONSE_ENDPOINT);
        attributes.put("6e400004-b5a3-f393-e0a9-e50e24dcca9e", CHARACTERISTIC_LIGHT_STICK_NORDIC_DATA_ENDPOINT);
    }

    public static String lookup(String uuid, String defaultName) {
        String name = attributes.get(uuid);
        return name == null ? defaultName : name;
    }
}
