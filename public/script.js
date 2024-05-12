const generateLocation = (page, limit, mode, search) => {
    if (search !== undefined && search !== '') {
        return `/cves/list?page=${page}&limit=${limit}&sortMode=${mode}&search=${search}`;
    }
    return `/cves/list?page=${page}&limit=${limit}&sortMode=${mode}`;
}

const pageClick = (page, limit, mode, search) => {
    window.location = generateLocation(page, limit, mode, search);
}

const leftClick = (curPage, limit, mode, search) => {
    if(parseInt(curPage) - 1 > 0){
        window.location = generateLocation((parseInt(curPage) - 1).toString(), limit, mode, search);
    } 
}

const rightClick = (curPage, limit, mode, search, totalRecords) => {
    if(parseInt(totalRecords) - ((parseInt(curPage)) * parseInt(limit)) > 0){
        window.location = generateLocation((parseInt(curPage) + 1).toString(), limit, mode, search);
    }
}

const setLimit = (curPage, limit, mode, search) => {
    window.location = generateLocation((parseInt(curPage)).toString(), limit, mode, search);
}

const detailHandler = (cveId) => {
    window.location = `/cves/${cveId}`;
}

const setSortMode = (curPage, limit, mode, search) => {
    const urlParams = new URLSearchParams(window.location.search);
    console.log(urlParams.get('sortMode'), mode);
    if (mode == '1') {
        if (urlParams.get('sortMode') == '1') {
            window.location = generateLocation((parseInt(curPage)).toString(), limit, mode, '2', search);
        } else {
            window.location = generateLocation((parseInt(curPage)).toString(), limit, mode, '1', search);
        }
    }
    else if (mode == '2') {
        if (urlParams.get('sortMode') == '3') {
            window.location = generateLocation((parseInt(curPage)).toString(), limit, mode, '4', search);
        } else {
            window.location = generateLocation((parseInt(curPage)).toString(), limit, mode, '3', search);
        }
    }
    else if (mode == '3') {
        if (urlParams.get('sortMode') == '5') {
            window.location = generateLocation((parseInt(curPage)).toString(), limit, mode, '5', search);
        } else {
            window.location = generateLocation((parseInt(curPage)).toString(), limit, mode, '5', search);
        }
    }
}