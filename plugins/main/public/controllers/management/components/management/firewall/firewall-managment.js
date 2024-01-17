/*
 * Wazuh app - React component for status
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
import React, { Component } from 'react';

class InvinsenseFireWall extends Component {
  constructor(props) {
    super(props);
  }

  render() {
    const containerStyle = {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      height: '100vh',
      textAlign: 'center',
      backgroundColor: '#282c34',
      color: 'white',
      fontFamily: 'Arial, sans-serif'
    };

    const headerStyle = {
      fontSize: '3rem',
      marginBottom: '20px'
    };

    const paragraphStyle = {
      fontSize: '1.5rem',
      marginBottom: '30px'
    };

    return (
      <div style={containerStyle}>
        <h1 style={headerStyle}>Coming Soon</h1>
        <p style={paragraphStyle}>This Features is under construction. We'll be here soon with our new awesome Plugins.</p>
      </div>
    );
  }
}

export default InvinsenseFireWall;
