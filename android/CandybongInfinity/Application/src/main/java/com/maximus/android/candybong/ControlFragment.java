package com.maximus.android.candybong;

import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.SeekBar;
import android.widget.Spinner;
import android.widget.TextView;

/**
 * A simple {@link Fragment} subclass.
 * Use the {@link ControlFragment#newInstance} factory method to
 * create an instance of this fragment.
 */
public class ControlFragment extends Fragment {

    // TODO: Rename parameter arguments, choose names that match
    // the fragment initialization parameters, e.g. ARG_ITEM_NUMBER
    private static final String ARG_PARAM1 = "param1";
    private static final String ARG_PARAM2 = "param2";

    // TODO: Rename and change types of parameters
    private String mParam1;
    private String mParam2;


    private ImageView colorPreview;
    private SeekBar redSeekBar, greenSeekBar, blueSeekBar;
    private Spinner modeSpinner;
    private Button applyButton, presetButton1, presetButton2, presetButton3;
    private TextView statusText;

    public ControlFragment() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @param param1 Parameter 1.
     * @param param2 Parameter 2.
     * @return A new instance of fragment ControlFragment.
     */
    // TODO: Rename and change types and number of parameters
    public static ControlFragment newInstance(String param1, String param2) {
        ControlFragment fragment = new ControlFragment();
        Bundle args = new Bundle();
        args.putString(ARG_PARAM1, param1);
        args.putString(ARG_PARAM2, param2);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mParam1 = getArguments().getString(ARG_PARAM1);
            mParam2 = getArguments().getString(ARG_PARAM2);
        }

    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View view =
                inflater.inflate(R.layout.fragment_control,
                        container, false);

        ((AppCompatActivity)getActivity()).getSupportActionBar().setTitle(R.string.app_name);


        colorPreview = view.findViewById(R.id.colorPreview);
        redSeekBar = view.findViewById(R.id.redSeekBar);
        greenSeekBar = view.findViewById(R.id.greenSeekBar);
        blueSeekBar = view.findViewById(R.id.blueSeekBar);
        modeSpinner = view.findViewById(R.id.modeSpinner);
        applyButton = view.findViewById(R.id.applyButton);
        presetButton1 = view.findViewById(R.id.presetButton1);
        presetButton2 = view.findViewById(R.id.presetButton2);
        presetButton3 = view.findViewById(R.id.presetButton3);
        statusText = view.findViewById(R.id.statusText);

        redSeekBar.setOnSeekBarChangeListener(seekBarChangeListener);
        greenSeekBar.setOnSeekBarChangeListener(seekBarChangeListener);
        blueSeekBar.setOnSeekBarChangeListener(seekBarChangeListener);

        modeSpinner.setOnItemSelectedListener(modeItemSelectedListener);

        applyButton.setOnClickListener(applyButtonClickListener);
        presetButton1.setOnClickListener(presetButtonClickListener);
        presetButton2.setOnClickListener(presetButtonClickListener);
        presetButton3.setOnClickListener(presetButtonClickListener);

        updateColorPreview();

        if (!BluetoothLeService.getInstance().isConnected()) {
            statusText.setBackgroundColor(Color.RED);
            statusText.setTextColor(Color.WHITE);
            statusText.setText("Not Connected");

            applyButton.setEnabled(false);
            presetButton1.setEnabled(false);
            presetButton2.setEnabled(false);
            presetButton3.setEnabled(false);
        }
        else {
            statusText.setVisibility(TextView.GONE);

            applyButton.setEnabled(true);
            presetButton1.setEnabled(true);
            presetButton2.setEnabled(true);
            presetButton3.setEnabled(true);
        }
        return view;
    }

    private final SeekBar.OnSeekBarChangeListener seekBarChangeListener = new SeekBar.OnSeekBarChangeListener() {
        @Override
        public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
            updateColorPreview();
        }

        @Override
        public void onStartTrackingTouch(SeekBar seekBar) {
            // Not used
        }

        @Override
        public void onStopTrackingTouch(SeekBar seekBar) {
            // Not used
        }
    };

    private final AdapterView.OnItemSelectedListener modeItemSelectedListener = new AdapterView.OnItemSelectedListener() {
        @Override
        public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
            // Handle mode selection
        }

        @Override
        public void onNothingSelected(AdapterView<?> parent) {
            // Not used
        }
    };

    private final View.OnClickListener applyButtonClickListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            BluetoothLeService.getInstance().doLedStaticColor(getColorSlider(), 10);
        }
    };

    private final View.OnClickListener presetButtonClickListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            // Handle preset selection
            switch(v.getId()) {
                case R.id.presetButton1:
                    BluetoothLeService.getInstance().doLedAnimation(1, 16);
                    break;
                case R.id.presetButton2:
                    BluetoothLeService.getInstance().doLedSpinHue(3, 16);
                    break;
                case R.id.presetButton3:
                    BluetoothLeService.getInstance().doLedAnimation(5, 16);
                    break;
            }
        }
    };

    private int getColorSlider() {
        int redValue = redSeekBar.getProgress();
        int greenValue = greenSeekBar.getProgress();
        int blueValue = blueSeekBar.getProgress();

        int color = Color.rgb(redValue, greenValue, blueValue);

        return color;
    }

    private void updateColorPreview() {
        int color = getColorSlider();

        Drawable bgDrawable = ContextCompat.getDrawable(getContext(), R.drawable.color_preview);
        bgDrawable.setColorFilter( color, PorterDuff.Mode.MULTIPLY );
        colorPreview.setBackground(bgDrawable);

        BluetoothLeService.getInstance().doLedStaticColor(getColorSlider(), 10);
    }
}