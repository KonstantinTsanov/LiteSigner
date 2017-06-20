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
package callbacks;

import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

/**
 * Contract between the device selection panel and the back-end.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface DevicePanel {

    /**
     * Gets the device table model.
     *
     * @return Model containing list of token descriptions.
     */
    public DefaultTableModel getTokensModel();

    /**
     * Gets panel's parent frame.
     *
     * @return The parent
     */
    public JFrame getPanelParent();

    /**
     * Gets the JTable in which the devices are displayed.
     *
     * @return The table showing the currently attached devices.
     */
    public JTable getTokensTable();

}
