/* 
 * The MIT License
 *
 * Copyright 2017 Konstantin Tsanov <k.tsanov@gmail.com>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package exceptions;

import java.util.Locale;
import java.util.ResourceBundle;
import lombok.Getter;

/**
 * Thrown when timestamping cannot be performed.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class TimestampingException extends Exception {

    public enum TimestampingError {
        TIMESTAMPING_VALIDATION_ERROR("timestampValidationError");
        @Getter
        private String bundleKey;

        private TimestampingError(String bundleKey) {
            this.bundleKey = bundleKey;
        }
    }
    private static final long serialVersionUID = 1L;

    private TimestampingError error;

    public TimestampingException(TimestampingError error) {
        this.error = error;
    }

    public TimestampingException(TimestampingError error, Throwable cause) {
        super(cause);
        this.error = error;
    }

    @Override
    public String getMessage() {
        ResourceBundle rb = ResourceBundle.getBundle("CoreBundle", Locale.US);
        return rb.getString(error.getBundleKey());
    }

    @Override
    public String getLocalizedMessage() {
        ResourceBundle rb = ResourceBundle.getBundle("CoreBundle");
        return rb.getString(error.getBundleKey());
    }
}
